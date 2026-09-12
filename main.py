"""Module to fetch and process the Emerging Threats Tor rules."""
import ipaddress
import re
import sys
import logging
import requests


EMERGING_THREATS_TOR_RULES_URL = "https://rules.emergingthreats.net/" \
    "blockrules/emerging-tor.rules"
OUTPUT_FILE_IP = "tor-ipv4-blocklist.txt"
OUTPUT_FILE_CIDR = "tor-ipv4-cidr-blocklist.txt"

# Dotted quads that are not adjacent to a word character or a dot, so that
# version-like tokens (v1.2.3.4) and longer dotted numbers (1.2.3.4.5) are not
# mistaken for addresses. The octet ranges are validated by ipaddress below.
IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)


logger = logging.getLogger(__name__)


def extract_ipv4_addresses(rules):
    """Return the globally routable IPv4 addresses found in the rules text."""
    addresses = []
    skipped_invalid = 0
    skipped_reserved = 0

    for match in IPV4_CANDIDATE_PATTERN.finditer(rules):
        candidate = match.group(0)

        try:
            address = ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            skipped_invalid += 1
            logger.debug("Ignoring malformed IPv4 candidate: %s", candidate)
            continue

        if not address.is_global or address.is_multicast:
            skipped_reserved += 1
            logger.debug("Ignoring non-routable IPv4 address: %s", candidate)
            continue

        addresses.append(str(address))

    if skipped_invalid or skipped_reserved:
        logger.warning(
            "Ignored %d malformed and %d non-routable IPv4 candidates.",
            skipped_invalid,
            skipped_reserved
        )

    return addresses


def main():
    """Main function to fetch and process the Emerging Threats Tor rules."""
    logging.basicConfig(level=logging.INFO)

    with requests.get(EMERGING_THREATS_TOR_RULES_URL, timeout=30) as response:
        if response.status_code != 200:
            logger.error(
                "Failed to fetch rules: %d",
                response.status_code
            )
            sys.exit(1)

        original_rules = response.text

        logger.info(
            "Fetched %d emerging-tor.rules successfully.",
            len(original_rules)
        )

        ip_list = extract_ipv4_addresses(original_rules)

    if not ip_list:
        logger.error(
            "No valid IPv4 addresses found in %d bytes of rules; "
            "refusing to overwrite the blocklists.",
            len(original_rules)
        )
        sys.exit(1)

    ip_list_cidr = [f"{address}/32" for address in ip_list]

    logger.info(
        "Found %s IPv4 addresses in the rules. Writing to files...",
        len(ip_list)
    )

    # Write normal IPv4 addresses list to file
    with open(OUTPUT_FILE_IP, 'w', encoding="utf-8") as f:
        f.writelines((str(i)+'\n' for i in ip_list))
        logger.info(
            "%d IPv4 addresses have been written successfully to %s.",
            len(ip_list),
            OUTPUT_FILE_IP
        )

    # Write CIDR IPv4 addresses list to file
    with open(OUTPUT_FILE_CIDR, 'w', encoding="utf-8") as f:
        f.writelines((str(i)+'\n' for i in ip_list_cidr))
        logger.info(
            "%d IPv4 addresses in CIDR notation have been written successfully to %s.",
            len(ip_list_cidr),
            OUTPUT_FILE_CIDR
        )


if __name__ == "__main__":
    main()
