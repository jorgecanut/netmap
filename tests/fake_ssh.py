#!/usr/bin/env python3
"""Stand-in for `ssh` in tests: answers the netmap-feed commands with sample
router output. The command is the last argument, as with real ssh."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import samples as S  # noqa: E402

cmd = sys.argv[-1]
out = sys.stdout
if cmd == "leases":
    out.write(S.LEASES)
elif cmd == "conntrack-snapshot":
    out.write("\n".join(S.SNAPSHOT) + "\n")
elif cmd == "conntrack-events":
    for line in (S.NEW_OUT, S.NEW_PORTFWD, S.NEW_INTERNAL, S.NEW_DNS_INTERNAL):
        out.write(line + "\n")
    out.flush()
    time.sleep(0.5)
    out.write(S.DESTROY_OUT + "\n")
    out.flush()
    time.sleep(60)
elif cmd == "dns":
    out.write("\n".join(S.DNS) + "\n")
    out.flush()
    time.sleep(60)
else:
    sys.stderr.write("netmap-feed: command not allowed: %s\n" % cmd)
    sys.exit(1)
