#!/usr/bin/env python3
"""Stand-in for ssh-keygen in tests: writes a dummy key pair to -f <path>."""

import sys

path = sys.argv[sys.argv.index("-f") + 1]
with open(path, "w") as f:
    f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
with open(path + ".pub", "w") as f:
    f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKE netmap\n")
