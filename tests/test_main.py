"""Tests for the Emerging Threats Tor rules processing script."""
import logging
import pytest

import main


# Shortened but structurally faithful excerpt of emerging-tor.rules. It mixes
# IPv4 and IPv6 nodes, duplicates and dotted non-address tokens on purpose.
SAMPLE_RULES = """\
# Emerging Threats Tor rules
#
alert ip [1.2.3.4,5.6.7.8,171.25.193.25] any -> $HOME_NET any (\
msg:"ET TOR Known Tor Exit Node Traffic group 1"; \
reference:url,doc.emergingthreats.net/bin/view/Main/TorRules; \
classtype:misc-attack; sid:2520000; rev:5555;)
alert ip $HOME_NET any -> [2001:db8::1,9.9.9.9,1.2.3.4] any (\
msg:"ET TOR Known Tor Exit Node Traffic group 2"; \
classtype:misc-attack; sid:2520001; rev:5555;)
"""

EXPECTED_IPS = [
    "1.2.3.4",
    "5.6.7.8",
    "171.25.193.25",
    "9.9.9.9",
    "1.2.3.4",
]


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` used as a context manager."""

    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


@pytest.fixture(name="output_files")
def output_files_fixture(tmp_path, monkeypatch):
    """Redirect both output files into a temporary directory."""
    ip_file = tmp_path / "tor-ipv4-blocklist.txt"
    cidr_file = tmp_path / "tor-ipv4-cidr-blocklist.txt"
    monkeypatch.setattr(main, "OUTPUT_FILE_IP", str(ip_file))
    monkeypatch.setattr(main, "OUTPUT_FILE_CIDR", str(cidr_file))
    return ip_file, cidr_file


@pytest.fixture(name="fake_get")
def fake_get_fixture(monkeypatch):
    """Replace ``requests.get`` with a recorder returning a canned response.

    The fixture yields a setter that installs the response to serve and
    records the call arguments in ``calls``.
    """
    calls = []

    def install(text="", status_code=200):
        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse(text=text, status_code=status_code)

        monkeypatch.setattr(main.requests, "get", fake_get)
        return calls

    return install


def read_lines(path):
    """Return the non-terminal lines of a written blocklist file."""
    return path.read_text(encoding="utf-8").splitlines()


@pytest.mark.usefixtures("output_files")
def test_fetches_the_emerging_threats_url_with_a_timeout(fake_get):
    """The rules are fetched from the documented URL with a timeout set."""
    calls = fake_get(text=SAMPLE_RULES)

    main.main()

    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == main.EMERGING_THREATS_TOR_RULES_URL
    assert url == (
        "https://rules.emergingthreats.net/blockrules/emerging-tor.rules"
    )
    assert kwargs["timeout"] == 30


def test_writes_every_extracted_ipv4_address(output_files, fake_get):
    """Each IPv4 address of the rules ends up in the plain blocklist."""
    ip_file, _ = output_files
    fake_get(text=SAMPLE_RULES)

    main.main()

    assert read_lines(ip_file) == EXPECTED_IPS


def test_writes_the_cidr_blocklist_with_a_32_suffix(output_files, fake_get):
    """The CIDR blocklist holds the same addresses as single-host /32 nets."""
    _, cidr_file = output_files
    fake_get(text=SAMPLE_RULES)

    main.main()

    assert read_lines(cidr_file) == [f"{ip}/32" for ip in EXPECTED_IPS]


def test_both_files_end_with_a_trailing_newline(output_files, fake_get):
    """Every entry is newline terminated so the files concatenate cleanly."""
    ip_file, cidr_file = output_files
    fake_get(text=SAMPLE_RULES)

    main.main()

    assert ip_file.read_text(encoding="utf-8").endswith("\n")
    assert cidr_file.read_text(encoding="utf-8").endswith("\n")


def test_ipv6_addresses_are_ignored(output_files, fake_get):
    """IPv6 nodes are skipped, as documented in the README."""
    ip_file, cidr_file = output_files
    rules = (
        "alert ip [2001:db8::1,fe80::1%eth0,2a0b:f4c2:2::1,9.9.9.9] any -> "
        "$HOME_NET any (sid:2520002;)\n"
    )
    fake_get(text=rules)

    main.main()

    assert read_lines(ip_file) == ["9.9.9.9"]
    assert read_lines(cidr_file) == ["9.9.9.9/32"]


def test_duplicate_addresses_are_kept(output_files, fake_get):
    """Addresses listed in several rule groups are emitted once per hit."""
    ip_file, _ = output_files
    fake_get(text="[1.2.3.4] [1.2.3.4] [1.2.3.4]")

    main.main()

    assert read_lines(ip_file) == ["1.2.3.4"] * 3


def test_addresses_are_written_in_the_order_they_appear(
    output_files, fake_get
):
    """The rule order is preserved instead of being sorted."""
    ip_file, _ = output_files
    fake_get(text="[9.9.9.9,1.1.1.1,5.5.5.5]")

    main.main()

    assert read_lines(ip_file) == ["9.9.9.9", "1.1.1.1", "5.5.5.5"]


def test_rules_without_addresses_abort_without_writing(
    output_files, fake_get
):
    """An address-less rules file must not truncate the published lists."""
    ip_file, cidr_file = output_files
    ip_file.write_text("1.2.3.4\n", encoding="utf-8")
    cidr_file.write_text("1.2.3.4/32\n", encoding="utf-8")
    fake_get(text="# no rules today\n")

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    assert excinfo.value.code == 1
    assert ip_file.read_text(encoding="utf-8") == "1.2.3.4\n"
    assert cidr_file.read_text(encoding="utf-8") == "1.2.3.4/32\n"


@pytest.mark.usefixtures("output_files")
def test_an_address_less_response_is_logged_as_an_error(fake_get, caplog):
    """The refusal to overwrite is visible in the workflow log."""
    fake_get(text="# no rules today\n")

    with caplog.at_level(logging.ERROR, logger=main.logger.name):
        with pytest.raises(SystemExit):
            main.main()

    assert "refusing to overwrite" in caplog.text


@pytest.mark.usefixtures("output_files")
@pytest.mark.parametrize("status_code", [301, 403, 404, 500, 503])
def test_a_non_200_response_exits_with_code_1(fake_get, status_code):
    """A failed download aborts instead of truncating the blocklists."""
    fake_get(text="", status_code=status_code)

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    assert excinfo.value.code == 1


def test_a_failed_download_leaves_the_existing_files_untouched(
    output_files, fake_get
):
    """The previous blocklists survive an outage of the rules server."""
    ip_file, cidr_file = output_files
    ip_file.write_text("1.2.3.4\n", encoding="utf-8")
    cidr_file.write_text("1.2.3.4/32\n", encoding="utf-8")
    fake_get(text="", status_code=500)

    with pytest.raises(SystemExit):
        main.main()

    assert ip_file.read_text(encoding="utf-8") == "1.2.3.4\n"
    assert cidr_file.read_text(encoding="utf-8") == "1.2.3.4/32\n"


@pytest.mark.usefixtures("output_files")
def test_a_failed_download_is_logged_as_an_error(fake_get, caplog):
    """Operators can see the failing status code in the workflow log."""
    fake_get(text="", status_code=503)

    with caplog.at_level(logging.ERROR, logger=main.logger.name):
        with pytest.raises(SystemExit):
            main.main()

    assert "503" in caplog.text


@pytest.mark.usefixtures("output_files")
def test_network_errors_are_not_swallowed(monkeypatch):
    """A connection error propagates so the GitHub Action fails loudly."""

    def boom(*_args, **_kwargs):
        raise main.requests.exceptions.ConnectionError("no route to host")

    monkeypatch.setattr(main.requests, "get", boom)

    with pytest.raises(main.requests.exceptions.ConnectionError):
        main.main()


def test_previous_content_is_overwritten_not_appended(
    output_files, fake_get
):
    """Re-running the script replaces the blocklists rather than growing."""
    ip_file, cidr_file = output_files
    ip_file.write_text("203.0.113.7\n" * 100, encoding="utf-8")
    fake_get(text="[1.2.3.4]")

    main.main()

    assert read_lines(ip_file) == ["1.2.3.4"]
    assert read_lines(cidr_file) == ["1.2.3.4/32"]


@pytest.mark.parametrize(
    "junk", ["999.1.2.3", "1.2.3.400", "1.2.3.4.5", "01.2.3.4", "1.2.3.04"]
)
def test_malformed_dotted_numbers_are_not_extracted(
    output_files, fake_get, junk
):
    """Non-addresses that merely look like dotted quads are dropped."""
    ip_file, _ = output_files
    fake_get(text=f"[8.8.8.8,{junk}]")

    main.main()

    assert read_lines(ip_file) == ["8.8.8.8"]


@pytest.mark.parametrize(
    "candidate",
    [
        "999.1.2.3",      # octet out of range
        "1.2.3.400",      # trailing octet out of range
        "256.256.256.256",
        "01.2.3.4",       # leading zero
        "1.2.3.04",
        "1.2.3.4.5",      # longer dotted number
        "1.2.3",          # too few octets
        "v1.2.3.4-beta",  # version token glued to a word
        "1.2.3.4abc",
    ],
)
def test_extract_rejects_malformed_candidates(candidate):
    """Only real dotted quads survive the extraction."""
    assert not main.extract_ipv4_addresses(candidate)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",         # RFC 1918
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",        # loopback
        "0.0.0.0",          # "this network"
        "0.4.8.1",          # a Tor version number would land here
        "169.254.1.1",      # link-local
        "100.64.0.1",       # CGNAT
        "192.0.2.1",        # TEST-NET-1
        "198.51.100.1",     # TEST-NET-2
        "203.0.113.7",      # TEST-NET-3
        "240.0.0.1",        # reserved
        "255.255.255.255",  # broadcast
        "224.0.0.1",        # multicast, which is_global alone does not catch
        "239.1.2.3",
    ],
)
def test_extract_drops_non_routable_addresses(address):
    """Blocking a LAN, loopback or reserved range would break the consumer."""
    assert not main.extract_ipv4_addresses(f"[{address}]")


@pytest.mark.parametrize(
    "address", ["1.0.0.1", "8.8.8.8", "171.25.193.25", "223.255.255.254"]
)
def test_extract_keeps_globally_routable_addresses(address):
    """Addresses at the edges of the routable space are still extracted."""
    assert main.extract_ipv4_addresses(f"[{address}]") == [address]


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        ("[1.2.3.4,5.6.7.8]", ["1.2.3.4", "5.6.7.8"]),
        ("1.2.3.4/32", ["1.2.3.4"]),
        ("$HOME_NET -> 1.2.3.4 any", ["1.2.3.4"]),
        ("sid:2520000; rev:5555; 1.2.3.4;", ["1.2.3.4"]),
        ("created_at 2008_12_01, updated_at 2026_01_01", []),
        ("doc.emergingthreats.net/bin/view/Main/TorRules", []),
    ],
)
def test_extract_handles_the_real_rule_syntax(rules, expected):
    """Surrounding rule punctuation neither hides nor invents addresses."""
    assert main.extract_ipv4_addresses(rules) == expected


def test_extract_logs_a_summary_of_skipped_candidates(caplog):
    """A malformed upstream file is visible without flooding the log."""
    rules = "[8.8.8.8,999.1.2.3,1.2.3.400,10.0.0.1]"

    with caplog.at_level(logging.WARNING, logger=main.logger.name):
        assert main.extract_ipv4_addresses(rules) == ["8.8.8.8"]

    assert "Ignored 2 malformed and 1 non-routable" in caplog.text


def test_extract_stays_quiet_when_everything_is_valid(caplog):
    """The nightly run logs no warning for a healthy rules file."""
    with caplog.at_level(logging.WARNING, logger=main.logger.name):
        main.extract_ipv4_addresses(SAMPLE_RULES)

    assert caplog.text == ""
