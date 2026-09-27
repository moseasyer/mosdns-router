"""The installer's port check, run against this machine's REAL `ss` output.

Not a test: a demonstration that the every-owner rule is reached by the shape `ss`
really prints, rather than by a fixture that agrees with the parser by accident.
The socket below is a real listening socket on a loopback HIGH port, held by a
parent and a child that inherited the descriptor -- one socket, two holders, one
`ss` line. The port number is not 53, and it is not supposed to be: this host's
resolver ports are off limits, and the preflight's own DNS port is passed in as a
parameter of :func:`_holders` + :func:`_is_exempt` rather than as a bind.

What this shows, and what only this can show:

  * `ss -H -lntup` names both pids on ONE line, in one `users:((...),(...))` field.
    A fixture that wrote a line per process describes two sockets, which is a
    different situation and was already refused.
  * the module's parser reads BOTH owners out of that one field, so
    ``_holders(...)[0].owners`` has length 2;
  * and the exemption is then asked the whole truth table about those two real
    pids, which is the only place the every-owner rule can be seen holding: both
    exempt passes, one exempt refuses, and a holder with no nameable owner
    refuses.

Usage, in the system-level test machine::

    setsid python3 shared_listener.py 18081 127.0.0.1 >/dev/null 2>/tmp/err.log &
    python3 port_check_against_real_ss.py 18081 /path/to/mosdns_installer.py

The module's path is an argument because this script is copied into the test
machine on its own: the installer is not installed there, and importing it from a
checkout is a filesystem path, not a package.
"""

import importlib.util
import subprocess
import sys


def load(path):
    """Import the installer from the path it was given, not from a package."""
    spec = importlib.util.spec_from_file_location("mosdns_installer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load(sys.argv[2])


def listeners():
    completed = subprocess.run(
        ["ss", "-H", "-lntup"], check=True, capture_output=True, text=True
    )
    return completed.stdout


def main():
    port = int(sys.argv[1])
    raw = listeners()
    print(f"=== ss -H -lntup, the line for {port} ===")
    line = next(one for one in raw.splitlines() if f":{port}" in one)
    print(line)

    holders = installer._holders(raw)
    holder = next(one for one in holders if one.port == port)
    print()
    print("=== what the module's parser read out of that ONE line ===")
    print(f"holders:      {len(holders)} (one per line, so one per socket)")
    print(f"owners:       {len(holder.owners)} -- {holder.owners}")
    if len(holder.owners) < 2:
        print("NO: this machine did not produce a shared-listener line; stop here.")
        return 1
    print(f"described as: {installer._describe_owners(holder)}")

    # The question the exemption exists for, asked about the socket that is really
    # there. `resolved_pid` is the main pid of one owner and `own_pids` the units
    # of this package's own; both are named by the SAME pids `ss` reported, so
    # every row below is a question about the real two holders, not a synthetic
    # pair. The address is the one this socket has, which is loopback -- so the
    # only thing separating the rows is WHO holds it.
    first, second = (owner.pid for owner in holder.owners)
    shared = holder  # both owners, as `ss` printed them
    alone = {first: installer.Owner("python3", first), second: installer.Owner("python3", second)}

    def only(which):
        """This socket, with just one of its real owners left on it."""
        return installer.Holder(
            protocol=holder.protocol, address=holder.address, port=holder.port, owners=[alone[which]]
        )

    print()
    print("=== the exemption, asked about that socket with the REAL pids ===")
    print("    (owner 1 treated as resolved's main pid, owner 2 as this package's unit)")
    print(f"  both owners, BOTH exempt          -> _is_exempt = "
          f"{installer._is_exempt(shared, first, {second: 'mosdns-router.service'})}")
    print(f"  both owners, only ONE exempt      -> _is_exempt = "
          f"{installer._is_exempt(shared, first, {})}")
    print(f"  both owners, only the other exempt-> _is_exempt = "
          f"{installer._is_exempt(shared, None, {first: 'mosdns-router.service'})}")
    print(f"  only resolved, on the stub address-> _is_exempt = "
          f"{installer._is_exempt(only(first), first, {})}")
    print(f"  only the other, a foreign pid     -> _is_exempt = "
          f"{installer._is_exempt(only(second), first, {})}")
    unnamed = installer.Holder(
        protocol=holder.protocol, address=holder.address, port=holder.port, owners=[]
    )
    print(f"  no owner at all                   -> _is_exempt = "
          f"{installer._is_exempt(unnamed, first, {})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
