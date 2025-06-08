# tor-ipv4-blocklist

This repository contains a script that compiles a text file with TOR IPv4 addresses from [Proofpoint's Emerging Tor Rules](https://rules.emergingthreats.net/blockrules/emerging-compromised.rules).
The script simply ignores IPv6 addresses from the Proofpoint's Emerging Tor Rules.

The TOR IPv4 blocklist is `tor-ipv4-blocklist.txt` in this repository.

The TOR IPv4 blocklist is downloadable—for example into your router configuration, e.g. via [pfBlocker-NG Package](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)—from: [https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-blocklist.txt](https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-blocklist.txt).

The IPv4 blocklist is updated every night at 01:45.

## Other Sources

Other sources of TOR node/exit node lists are:
 * [Proofpoint Emerging Threats Rules](https://rules.emergingthreats.net/blockrules/emerging-compromised.rules)
 * [dan.me.uk](https://www.dan.me.uk/tornodes)

## License

Please refer to [LICENSE](LICENSE)