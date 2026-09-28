#!/bin/sh
# Make NetworkManager manage eth0, and refuse to continue if it does not.
#
# Run once, at boot, by target-nm-setup.service. Not by a scenario: the window
# where the target is unmanaged is exactly the window in which a scenario failure
# would read like a bug in a package that has not been installed yet.
#
# ## The order, and why each step is where it is
#
# Three measured facts, all re-measured on this host in this session against the
# real 24.04 image, and none of them obvious:
#
#   1. A connection profile must exist for the device FIRST. With no profile,
#      `nmcli device set eth0 managed yes` **returns success** -- the audit log
#      records `op="device-managed" interface="eth0" … result="success"` -- and
#      `GENERAL.NM-MANAGED` is still `no` after the restart. It was measured on
#      every container tried, and it is what the previous plan's Task 2 and Task 3
#      disagreed about: whoever creates the profile has to do it before this
#      script runs, and the image creates it here rather than leaving it to a
#      scenario that runs later.
#
#   2. The override needs the restart. `nmcli device set` writes an override under
#      `/run/NetworkManager/devices/` and NetworkManager only re-reads it on
#      restart. Without step 3 the command succeeds, does nothing, and the honest
#      conclusion is that the harness is wrong.
#
#   3. The device has to be a bridge network's `eth0` of type `ethernet`. Podman's
#      default rootless network hands a container a `tun/tap` device and
#      NetworkManager refuses that type by design, so step 1 cannot succeed at all
#      and this script's check reports the real cause instead of `no`.
#
# The order is asserted by a test that RUNS this script against a model of `nmcli`
# and `systemctl`, with the profile step moved after the restart -- the mutation
# that must make the check fail. It is not a search for three strings in a file.

set -eu

DEVICE=eth0
PROFILE=eth0-managed
MANAGED_FIELD=GENERAL.NM-MANAGED
TYPE_FIELD=GENERAL.TYPE
# The one type NetworkManager will manage. Everything else -- the tun/tap device
# of Podman's default rootless network above all -- is refused by design.
WANTED_TYPE=ethernet

# Wait for NetworkManager to answer before asking it anything.
#
# `After=NetworkManager.service` orders the *job*, not the daemon's readiness:
# nmcli can lose the race with a daemon that is starting, and a spurious failure
# here would look like the managed-device problem it is not. Bounded, and the
# bound is short, because a NetworkManager that never answers is a different
# failure and the check below reports it as one.
attempt=0
until nmcli general status >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "target-nm-setup: NetworkManager did not answer 'nmcli general status' after 30 attempts." >&2
        echo "target-nm-setup: this target cannot be measured, and a scenario failure from here" >&2
        echo "target-nm-setup: would read like a bug in a package that is not installed yet." >&2
        exit 1
    fi
    sleep 1
done

# 1. The connection profile. FIRST, and not as an afterthought: with no profile
#    for the device, step 2 is accepted and discarded.
#
#    Guarded, because `nmcli connection add` with a name that already exists does
#    not fail -- it warns and creates another. Measured on this host, after the
#    unit had been restarted once by the `Requires=` cycle described in
#    target-nm-setup.service:
#
#      Warning: There are 4 other connections with the name 'eth0-managed'.
#
#    Several profiles for one device would make Task 3's
#    `nmcli connection up eth0-managed` ambiguous. The command, the name and the
#    order are the measured ones; what the guard adds is that re-running the unit
#    is not destructive, which systemd does after any restart.
if ! nmcli connection show "$PROFILE" >/dev/null 2>&1; then
    nmcli connection add type ethernet ifname "$DEVICE" con-name "$PROFILE" ipv4.method auto
fi

# 2 and 3. The override and the restart that re-reads it, **only where
#    NetworkManager has a persistent device override to re-read.**
#
#    Measured on this host, with the profile above present, on five releases:
#
#        nmcli 1.36.6  22.04   three steps -> no    no `managed=true` as input
#        nmcli 1.42.4  23.04   three steps -> no    no `managed=true` as input
#        nmcli 1.44.2  23.10   three steps -> yes   `managed=true` re-read
#        nmcli 1.46.0  24.04   three steps -> yes   `managed=true` re-read
#        nmcli 1.54.3  26.04   three steps -> yes   `managed=true` re-read
#
#    "as input" is the careful half. On 22.04 the override file *does* grow a
#    `managed=true` key once something else has made the device managed -- that is
#    NetworkManager recording state it already has. With the declaration removed,
#    the command is accepted, the restart happens, the field stays `no` and no key
#    appears. So the discriminator is the field, and the key is a consequence.
#
#    So the boundary is 1.44, and the two sides are adjacent releases: 1.42.4
#    fails and 1.44.2 works, with nothing in between to be excused. Below it the
#    command is *accepted* and changes nothing, and running it anyway would print
#    a success that means nothing -- which is exactly how an operator ends up
#    concluding the harness is wrong.
#
#    22.04 is not left unmanaged by skipping this: the image declares the device
#    managed in /etc/NetworkManager/conf.d/10-mosdns-target.conf, and the check
#    below is what decides whether that declaration took effect.
#
#    The gate's failure direction is the safe one. A version wrongly read as old
#    skips two commands whose effect the declaration already provides; a version
#    wrongly read as new runs a sequence measured to do nothing. So the cost of a
#    wrong answer is silence rather than an unmanaged device.
nm_version=$(nmcli --version 2>&1 | sed -n 's/.*version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
nm_major=${nm_version%%.*}
nm_minor=${nm_version#*.}
nm_minor=${nm_minor%%.*}
if [ -z "$nm_version" ] || [ "$nm_major" -gt 1 ] || { [ "$nm_major" -eq 1 ] && [ "$nm_minor" -ge 44 ]; }; then
    # 2. The override. Returns success on its own and does not take effect.
    nmcli device set "$DEVICE" managed yes

    # 3. The restart that re-reads the override written under
    #    /run/NetworkManager/devices/. Not optional: step 2 without it is a lie.
    systemctl restart NetworkManager
else
    echo "target-nm-setup: this NetworkManager ($(nmcli --version 2>&1 | tr '\n' ' ')) has no" >&2
    echo "target-nm-setup: persistent device override, so 'nmcli device set $DEVICE managed" >&2
    echo "target-nm-setup: yes' would be accepted and would change nothing, and no restart could" >&2
    echo "target-nm-setup: re-read it. Skipping both; the managed state comes from the conf.d" >&2
    echo "target-nm-setup: declaration, and the check below is what decides whether it took effect." >&2
fi

# The check, and it asserts BOTH facts rather than only the field.
#
# A check on the field alone would pass on an entrypoint that had the steps in the
# wrong order, provided something later created a profile -- which is the exact
# shape the plan's amendment closed. So the profile's existence is checked, and a
# failure reports both facts: `eth0-managed` missing and the value that was
# observed. A message that said only "NM-MANAGED is no" would send the reader to
# run steps 2 and 3, watch them succeed, and conclude the harness was wrong.
profile_state=$(nmcli connection show "$PROFILE" 2>&1 || true)
managed=$(nmcli -g "$MANAGED_FIELD" device show "$DEVICE" 2>&1 || true)
device_type=$(nmcli -g "$TYPE_FIELD" device show "$DEVICE" 2>&1 || true)

if [ -z "$profile_state" ] || printf '%s' "$profile_state" | grep -qi "^Error"; then
    echo "target-nm-setup: refusing to continue -- the connection profile '$PROFILE' for" >&2
    echo "target-nm-setup: $DEVICE does not exist, and without it the override above is" >&2
    echo "target-nm-setup: accepted and discarded. Create it and re-run this unit:" >&2
    echo "target-nm-setup:   nmcli connection add type ethernet ifname $DEVICE con-name $PROFILE ipv4.method auto" >&2
    echo "target-nm-setup: ('nmcli connection show $PROFILE' answered: ${profile_state:-nothing})" >&2
    exit 1
fi

if [ "$device_type" != "$WANTED_TYPE" ]; then
    echo "target-nm-setup: refusing to continue -- $DEVICE is of type '$device_type', not" >&2
    echo "target-nm-setup: '$WANTED_TYPE', and NetworkManager refuses a device that is not an" >&2
    echo "target-nm-setup: ethernet one by design. Podman's DEFAULT rootless network hands a" >&2
    echo "target-nm-setup: container a tun/tap device, so this target is on the wrong network:" >&2
    echo "target-nm-setup: it must be on a netavark BRIDGE network (podman network create)." >&2
    echo "target-nm-setup: ($MANAGED_FIELD was '$managed'.)" >&2
    exit 1
fi

if [ "$managed" != "yes" ]; then
    echo "target-nm-setup: refusing to continue -- 'nmcli -g $MANAGED_FIELD device show $DEVICE'" >&2
    echo "target-nm-setup: answered '$managed', not 'yes'. Two mechanisms are supposed to" >&2
    echo "target-nm-setup: produce 'yes' here, and between them they did not:" >&2
    echo "target-nm-setup:   1. the declaration -- /etc/NetworkManager/conf.d/10-mosdns-target.conf" >&2
    echo "target-nm-setup:      narrows NetworkManager's shipped unmanaged-devices list with" >&2
    echo "target-nm-setup:      'except:interface-name:$DEVICE'. If that file is present and the" >&2
    echo "target-nm-setup:      field is still '$managed', the declaration did not take effect." >&2
    echo "target-nm-setup:   2. the sequence, which ran only if NetworkManager has a persistent" >&2
    echo "target-nm-setup:      device override -- it has one from 1.44, and this one is" >&2
    echo "target-nm-setup:      $(nmcli --version 2>&1 | tr '\n' ' ')" >&2
    echo "target-nm-setup: ('cat /etc/NetworkManager/conf.d/10-mosdns-target.conf' and" >&2
    echo "target-nm-setup: 'journalctl -u NetworkManager' in this target.)" >&2
    exit 1
fi

echo "target-nm-setup: NetworkManager manages $DEVICE (type $device_type, profile $PROFILE)."
exit 0
