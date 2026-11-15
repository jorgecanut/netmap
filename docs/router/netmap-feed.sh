#!/bin/sh
# NetMap router feed - install on the OpenWrt router as /usr/bin/netmap-feed
# (chmod 755). NetMap's SSH key is locked to this script in
# /etc/dropbear/authorized_keys, so the key can run these four read-only
# commands and nothing else. See docs/ROUTER.md.

case "$SSH_ORIGINAL_COMMAND" in
    conntrack-snapshot)
        # every connection open right now
        exec conntrack -L -o id ;;
    conntrack-events)
        # each connection as it opens and closes, with a timestamp
        exec conntrack -E -e NEW,DESTROY -o timestamp,id ;;
    dns)
        # dnsmasq query log (needs logqueries=1) -> which name each IP came from
        exec logread -f -e dnsmasq ;;
    leases)
        # DHCP leases -> device names
        exec cat /tmp/dhcp.leases ;;
    *)
        echo "netmap-feed: command not allowed: '$SSH_ORIGINAL_COMMAND'" >&2
        exit 1 ;;
esac
