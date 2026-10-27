"""Tests for SOC exports: STIX 2.1, MISP and syslog for Wazuh."""

from __future__ import annotations

import json
import re
import socket
import threading

import pytest
from typer.testing import CliRunner

from otacon import soc
from otacon.cli import app
from otacon.models import Discovery, DomainResult, PermutationType, ScanReport
from otacon.theme import RiskLevel


def _report(target: str = "example.com") -> ScanReport:
    return ScanReport(
        target=target,
        results=[
            DomainResult(
                domain="exampel.com",
                kind=PermutationType.TYPO,
                resolves=True,
                has_mx=True,
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                risk_reasons=["has an MX record (+25)"],
                intel_sources=["OpenPhish"],
                ip_addresses=["203.0.113.9"],
                asn=13335,
            ),
            DomainResult(
                domain="exmple.com",
                kind=PermutationType.TYPO,
                resolves=True,
                risk_score=20,
                risk_level=RiskLevel.LOW,
            ),
        ],
        discovered=[
            Discovery(host="example.id-1.click", sources=["Phishing Army"]),
            Discovery(host="example-pay.com", sources=["CT"]),
        ],
    )


def test_stix_bundle_has_one_indicator_per_exportable_domain() -> None:
    bundle = json.loads(soc.to_stix([_report()]))
    assert bundle["type"] == "bundle"
    indicators = {o["name"]: o for o in bundle["objects"] if o["type"] == "indicator"}
    # The low-risk variant is context, not an indicator.
    assert set(indicators) == {"exampel.com", "example.id-1.click", "example-pay.com"}
    exampel = indicators["exampel.com"]
    assert exampel["pattern"] == "[domain-name:value = 'exampel.com']"
    assert exampel["indicator_types"] == ["malicious-activity"]  # reported by a feed
    assert exampel["confidence"] == 90 and exampel["spec_version"] == "2.1"
    assert indicators["example-pay.com"]["indicator_types"] == ["anomalous-activity"]  # CT only
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z", exampel["valid_from"])


def test_stix_ids_are_stable_and_shared_hosts_are_not_duplicated() -> None:
    first = json.loads(soc.to_stix([_report()]))
    again = json.loads(soc.to_stix([_report(), _report("example.net")]))
    ids = lambda b: sorted(o["id"] for o in b["objects"] if o["type"] == "indicator")  # noqa: E731
    assert ids(first) == ids(again)


def test_stix_pattern_quoting() -> None:
    assert soc._stix_quote("a'b\\c") == "a\\'b\\\\c"


def test_misp_event_marks_high_risk_for_ids() -> None:
    event = json.loads(soc.to_misp([_report()]))["Event"]
    attrs = {a["value"]: a for a in event["Attribute"]}
    assert set(attrs) == {"exampel.com", "example.id-1.click", "example-pay.com"}
    assert attrs["exampel.com"]["to_ids"] is True
    assert attrs["example-pay.com"]["to_ids"] is False  # CT sighting: no blocking
    assert event["threat_level_id"] == "1" and event["distribution"] == "0"
    assert {"name": "tlp:amber"} in event["Tag"]


def test_syslog_line_is_rfc3164_with_wazuh_friendly_json() -> None:
    [line] = soc.syslog_lines(_report())
    m = re.fullmatch(r"<(\d+)>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) otacon: (\{.*\})", line)
    assert m, line
    assert m.group(1) == "10"  # user.crit for a critical finding
    body = json.loads(m.group(4))["otacon"]
    assert body["domain"] == "exampel.com" and body["risk_level"] == "critical"
    assert body["signals"] == ["dns", "mx"] and body["asn"] == 13335


def test_watch_lines_carry_the_event_kind() -> None:
    from otacon.watch import Event

    [line] = soc.watch_lines("example.com", [Event("new", "exampel.com", "registered", "high")])
    body = json.loads(line.split("otacon: ", 1)[1])["otacon"]
    assert body["event"] == "watch.new" and line.startswith("<10>")


def test_send_syslog_over_udp_and_tcp() -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    assert soc.send_syslog(["<12>hello"], f"udp://127.0.0.1:{udp.getsockname()[1]}") == 1
    assert udp.recv(100) == b"<12>hello"
    udp.close()

    srv = socket.create_server(("127.0.0.1", 0))
    got: list[bytes] = []

    def accept() -> None:
        conn, _ = srv.accept()
        with conn:
            got.append(conn.recv(100))

    t = threading.Thread(target=accept)
    t.start()
    soc.send_syslog(["a", "b"], f"tcp://127.0.0.1:{srv.getsockname()[1]}")
    t.join(5)
    srv.close()
    assert got == [b"a\nb\n"]


@pytest.mark.parametrize("bad", ["http://siem:514", "udp://:514", "ftp://x"])
def test_send_syslog_rejects_other_schemes(bad: str) -> None:
    with pytest.raises(ValueError):
        soc.send_syslog(["x"], bad)


def test_cli_writes_stix_and_misp(tmp_path, monkeypatch) -> None:
    async def fake_run_scan(target, concurrency, check_http, **kw):
        return _report(target)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["scan", "example.com", "--stix", "out.stix.json", "--misp", "out.misp.json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "out.stix.json").read_text())["type"] == "bundle"
    assert "Event" in json.loads((tmp_path / "out.misp.json").read_text())


def test_cli_reports_a_bad_syslog_destination_without_crashing(monkeypatch) -> None:
    async def fake_run_scan(target, concurrency, check_http, **kw):
        return _report(target)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    result = CliRunner().invoke(app, ["scan", "example.com", "--syslog", "http://nope"])
    assert result.exit_code == 0
    assert "Error sending to syslog" in result.output
