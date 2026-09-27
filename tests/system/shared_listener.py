"""Listening sockets on high ports, inherited across a fork, for `ss` to report.

Not a test: the thing that produces a real `ss` line to copy into a fixture. The
installer reads `ss -H -lntup` and reasons about who holds each socket, and a
hand-written line can agree with a parser that is wrong in the same direction --
which is how the version before this one read the send-queue length as a port.

Two questions this exists to answer, both answered by running it in the
system-level test machine rather than by writing the line out:

  * how does `ss` print ONE socket held by TWO processes?  One line, with both
    pids inside a single ``users:((...),(...))`` field -- not a line per process.
    No SO_REUSEPORT is involved: the child is born holding the listening
    descriptor, so there is one socket and two holders, and the foreign holder
    never had to agree to anything.  This is the shape the port check's
    every-owner-must-be-exempt rule exists for.

  * how does `ss` print an IPv6 local address, brackets included?  The fixtures
    have to carry the real spelling, because a loopback test written as a bare
    ``::1`` would pass a parser that only handles the bracketed form and fail the
    one `ss` actually produces.

Usage, on the test machine::

    python3 shared_listener.py 18081 127.0.0.1     # one socket, two holders
    python3 shared_listener.py 15399 '[::1]'        # the IPv6 spelling
    ss -H -lntup | grep -E '18081|15399'
"""

import os
import socket
import sys
import time

port = int(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
family = socket.AF_INET6 if ":" in host else socket.AF_INET

listener = socket.socket(family, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    listener.bind((host, port))
except OSError as failure:
    # A container has no global IPv6 address to bind, which is a fact about the
    # container and not a failure of the demonstration: the loopback spelling is
    # the one that matters, and `ss` prints both from the same code.
    sys.stderr.write(f"bind {host}:{port} failed: {failure}\n")
    raise SystemExit(1)
listener.listen(5)

pid = os.fork()
if pid == 0:
    # The child never touches the socket; it only holds the descriptor it was
    # born with, and that is enough for `ss` to name it beside its parent.
    os.setsid()
    sys.stderr.write(f"child pid {os.getpid()} holds the inherited fd\n")
    sys.stderr.flush()
    time.sleep(600)

sys.stderr.write(f"parent pid {os.getpid()} listening on {host}:{port}, child {pid}\n")
sys.stderr.flush()
sys.stdout.write("READY\n")
sys.stdout.flush()
time.sleep(600)
