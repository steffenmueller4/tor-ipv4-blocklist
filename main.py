"""Module to fetch and process the Emerging Threats Tor rules."""
import re
import sys
import logging
import requests


EMERGING_THREATS_TOR_RULES_URL = "https://rules.emergingthreats.net/" \
    "blockrules/emerging-tor.rules"
OUTPUT_FILE = "tor-ipv4-blocklist.txt"


logger = logging.getLogger(__name__)


def main():
    """Main function to fetch and process the Emerging Threats Tor rules."""
    logging.basicConfig(level=logging.INFO)

    ip_list = []
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

        for tor_ipv4 in re.finditer(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", original_rules
        ):
            ipv4_cidr = tor_ipv4.group(0) + "/32"
            ip_list.append(ipv4_cidr)

    logger.info(
        "Found %s IPv4 addresses in the rules. Writing to %s...",
        len(ip_list),
        OUTPUT_FILE
    )

    with open(OUTPUT_FILE, 'w', encoding="utf-8") as f:
        f.writelines((str(i)+'\n' for i in ip_list))
    
    logger.info(
        "%s IPv4 addresses have been written successfully to %s.",
        len(ip_list),
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()
