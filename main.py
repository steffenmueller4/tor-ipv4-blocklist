import requests
import re
import sys
import logging


EMERGING_THREATS_TOR_RULES_URL = "https://rules.emergingthreats.net/" \
    "blockrules/emerging-tor.rules"
OUTPUT_FILE = "tor-ipv4-blocklist.txt"


logger = logging.getLogger(__name__)


def main():
    """Main function to fetch and process the Emerging Threats Tor rules."""
    logging.basicConfig(level=logging.INFO)

    ip_list = []
    with requests.get(EMERGING_THREATS_TOR_RULES_URL) as response:
        if response.status_code != 200:
            logger.error(
                f"Failed to fetch rules: {response.status_code}"
            )
            sys.exit(1)

        original_rules = response.text

        logger.info(
            f"Fetched {len(original_rules)} emerging-tor.rules successfully."
        )

        for tor_ipv4 in re.finditer(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", original_rules
        ):
            ipv4_cidr = tor_ipv4.group(0) + "/32"
            ip_list.append(ipv4_cidr)

    logger.info(
        f"Found {len(ip_list)} IPv4 addresses in the rules. "
        f"Writing to {OUTPUT_FILE}..."
    )
    with open(OUTPUT_FILE, 'w') as f:
        f.writelines((str(i)+'\n' for i in ip_list))


if __name__ == "__main__":
    main()
