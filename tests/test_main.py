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
        "alert ip [2001:db8::1,fe80::1%eth0,2a0b:f4c2:2::1] any -> "
        "$HOME_NET any (sid:2520002;)\n"
    )
    fake_get(text=rules)

    main.main()

    assert read_lines(ip_file) == []
    assert read_lines(cidr_file) == []


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


def test_empty_rules_produce_empty_files(output_files, fake_get):
    """A rules file without any address still produces both output files."""
    ip_file, cidr_file = output_files
    fake_get(text="# no rules today\n")

    main.main()

    assert ip_file.read_text(encoding="utf-8") == ""
    assert cidr_file.read_text(encoding="utf-8") == ""


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


@pytest.mark.xfail(
    reason="the extraction regex does not validate octet ranges or "
           "dotted-quad boundaries",
    strict=True,
)
@pytest.mark.parametrize("text", ["999.1.2.3", "1.2.3.400", "1.2.3.4.5"])
def test_malformed_dotted_numbers_are_not_extracted(
    output_files, fake_get, text
):
    """Known gap: non-addresses that look like dotted quads slip through."""
    ip_file, _ = output_files
    fake_get(text=text)

    main.main()

    assert read_lines(ip_file) == []
