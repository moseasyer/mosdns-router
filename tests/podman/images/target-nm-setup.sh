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

# 2. The override. Returns success on its own and does not take effect.
nmcli device set "$DEVICE" managed yes

# 3. The restart that re-reads the override written under
#    /run/NetworkManager/devices/. Not optional, and step 2 without it is a lie.
systemctl restart NetworkManager

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
    echo "target-nm-setup: answered '$managed', not 'yes', even though the connection profile" >&2
    echo "target-nm-setup: '$PROFILE' exists and NetworkManager was restarted." >&2
    # The NetworkManager version, because the cause is not the same on every
    # release and the two causes look identical from the outside. Measured on
    # this host against these three images:
    #
    #   nmcli 1.46 (24.04), 1.54 (26.04) -- the override is written under
    #     /run/NetworkManager/devices/ and the restart re-reads it. The restart
    #     is what to look at if it says no.
    #   nmcli 1.36 (22.04) -- there is no persistent device override in this
    #     version at all. `nmcli device set eth0 managed yes` is accepted, the
    #     audit log records `op="device-managed" ... result="success"`, the file
    #     under /run/NetworkManager/devices/ gets no `managed=true` key, and the
    #     field stays `no` with or without the restart and with or without a
    #     profile. Nothing in this script can change that, and the check is here
    #     so the reason is the one above rather than a scenario failing later.
    echo "target-nm-setup: NetworkManager here is $(nmcli --version 2>&1 | tr '\n' ' ')" >&2
    echo "target-nm-setup: ('journalctl -u NetworkManager' in this target, then" >&2
    echo "target-nm-setup: 'cat /run/NetworkManager/devices/*' to see whether the override was" >&2
    echo "target-nm-setup: written at all.)" >&2
    exit 1
fi

echo "target-nm-setup: NetworkManager manages $DEVICE (type $device_type, profile $PROFILE)."
exit 0
