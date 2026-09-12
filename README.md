# tor-ipv4-blocklist

This repository contains a Python script (`main.py`) that compiles text files with TOR IPv4 addresses (`tor-ipv4-blocklist.txt` or `tor-ipv4-cidr-blocklist.txt`) from [Proofpoint's Emerging Tor Rules](https://rules.emergingthreats.net/blockrules/emerging-compromised.rules).
The script just uses IPv4 addresses and simply ignores IPv6 addresses from the Proofpoint's Emerging Tor Rules.
Extracted addresses are validated before they are written: malformed dotted quads and non-routable addresses (private, loopback, link-local, reserved, broadcast and multicast ranges) are dropped, and a rules file that yields no valid address at all aborts the run instead of overwriting the blocklists with empty files.
The TOR IPv4 blocklists are `tor-ipv4-blocklist.txt` (IPv4 addresses) and `tor-ipv4-cidr-blocklist.txt` (IPv4 addresses in CIDR notation) in this repository.

The up-to-date TOR IPv4 blocklist is downloadable from: [TOR IPv4 Blocklist](https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-blocklist.txt) or [TOR IPv4 Blocklist in CIDR notation](https://raw.githubusercontent.com/steffenmueller4/tor-ipv4-blocklist/refs/heads/main/tor-ipv4-cidr-blocklist.txt).
Thus, you can use those links to to be used in your router's configuration such as via [pfBlocker-NG Package](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html) or as an Alias in your OPNsense rules as explained [here](https://docs.opnsense.org/manual/how-tos/drop.html).

The IPv4 blocklist is updated every night.
As the generation relies on a [scheduled GitHub Action](/.github/workflows/update-blocklist.yml), there is no guaratuee that the file is refreshed at a specific time.

## Development

Install the dependencies and run the test suite with:

```
make init
make test
```

The tests in [tests/test_main.py](tests/test_main.py) run offline: the HTTP request to the Emerging Threats rules is stubbed out and the blocklists are written to a temporary directory.
They are also executed by a [GitHub Action](/.github/workflows/tests.yml) on every push that touches the Python code.

## Other Sources

Other sources of TOR node/exit node lists are:
 * [Proofpoint Emerging Threats Rules](https://rules.emergingthreats.net/blockrules/emerging-compromised.rules)
 * [dan.me.uk](https://www.dan.me.uk/tornodes)

## License

Please refer to [LICENSE](LICENSE)