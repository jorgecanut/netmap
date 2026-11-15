import logging

# Tests provoke failures on purpose; keep their expected warnings out of the output.
# Set NETMAP_TEST_LOG=1 to see them while debugging a test.
import os

if not os.environ.get("NETMAP_TEST_LOG"):
    logging.disable(logging.CRITICAL)
