#!/usr/bin/env python3
"""NetMap - a live world map of your computer's and your network's connections.

    python netmap.py                 open http://localhost:8339
    python netmap.py --help          all options (each has an environment variable)

The code lives in netmap_core/; see docs/ARCHITECTURE.md.
"""

import os
import sys

# pythonw.exe (NetMap.bat) gives the process no console: print() goes nowhere
# and a crash leaves no trace. Send everything to netmap.log instead.
if sys.stdout is None or sys.stderr is None:
    _dir = os.environ.get("NETMAP_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
    try:
        _log = open(os.path.join(_dir, "netmap.log"), "a", encoding="utf-8", buffering=1)
    except OSError:
        _log = open(os.devnull, "w")
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log

if sys.version_info < (3, 8):
    sys.exit("NetMap needs Python 3.8 or newer (this is %s)" % sys.version.split()[0])

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging       # noqa: E402
import threading     # noqa: E402


def _log_crash(where, exc_type, exc, tb):
    logging.getLogger("netmap").critical("unhandled %s in %s", exc_type.__name__, where,
                                         exc_info=(exc_type, exc, tb))


sys.excepthook = lambda t, v, tb: _log_crash("main thread", t, v, tb)
threading.excepthook = lambda a: _log_crash(
    "thread %s" % getattr(a.thread, "name", "?"), a.exc_type, a.exc_value, a.exc_traceback)

from netmap_core.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
