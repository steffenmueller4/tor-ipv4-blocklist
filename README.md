# tor-ipv4-blocklist

This repository contains a script that compiles a text file with TOR IPv4 addresses from [https://rules.emergingthreats.net/blockrules/emerging-compromised.rules](Proofpoint's Emerging Tor Rules).
It simply ignores IPv6 addresses from the Proofpoint's Emerging Tor Rules.

The TOR IPv4 blocklist is `tor-ipv4-blocklist.txt` in this repository.

The TOR IPv4 blocklist is downloadable—for example into your router configuration, e.g. via [https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html](pfBlocker-NG Package))—from: [https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-blocklist.txt](https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-blocklist.txt).

The IPv4 blocklist is updated every night at 01:45.

## Other Sources

Other sources of TOR node/exit node lists are:
 * [https://rules.emergingthreats.net/blockrules/emerging-compromised.rules](Proofpoint Emerging Threats Rules)
 * [https://www.dan.me.uk/tornodes](dan.me.uk)
