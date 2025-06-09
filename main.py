"""Module to fetch and process the Emerging Threats Tor rules."""
import re
import sys
import logging
import requests


EMERGING_THREATS_TOR_RULES_URL = "https://rules.emergingthreats.net/" \
    "blockrules/emerging-tor.rules"
OUTPUT_FILE_IP = "tor-ipv4-blocklist.txt"
OUTPUT_FILE_CIDR = "tor-ipv4-cidr-blocklist.txt"


logger = logging.getLogger(__name__)


def main():
    """Main function to fetch and process the Emerging Threats Tor rules."""
    logging.basicConfig(level=logging.INFO)

    ip_list = []
    ip_list_cidr = []
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

        for extracted_ipv4 in re.finditer(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            original_rules
        ):
            tor_ipv4 = extracted_ipv4.group(0)
            ip_list.append(tor_ipv4)
            ip_list_cidr.append(f"{tor_ipv4}/32")

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
