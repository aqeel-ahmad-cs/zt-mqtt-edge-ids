"""
Tests the mitigation layer against mocked subprocess calls rather than a
live iptables binary, since CI runners and most dev laptops shouldn't
need root or a real netfilter stack just to validate this logic.
"""

import json
import subprocess
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.mitigation.firewall_controller import FirewallController, FirewallControllerError
from src.mitigation.quarantine_ledger import QuarantineLedger


def _mock_success(*args, **kwargs):
    return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")


def _mock_failure_result(stderr_message):
    # side_effect lists return values as-is when the entry is not itself
    # an exception, so we build the CompletedProcess directly here rather
    # than handing back a function object that mock would just return
    # unevaluated
    return subprocess.CompletedProcess(["iptables"], returncode=1, stdout="", stderr=stderr_message)


class TestFirewallControllerChainSetup:
    @patch("subprocess.run")
    def test_creates_chain_on_first_init(self, mock_run):
        mock_run.side_effect = [
            _mock_success(),   # -N chain creation succeeds
            _mock_success(),   # -C jump rule check succeeds (already present)
        ]
        controller = FirewallController(dry_run=False)
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_reuses_existing_chain_gracefully(self, mock_run):
        mock_run.side_effect = [
            _mock_failure_result("iptables: Chain already exists."),
            _mock_success(),
        ]
        # should not raise despite the "failure" on chain creation
        controller = FirewallController(dry_run=False)
        assert controller.chain == "ZT_MQTT_QUARANTINE"


class TestFirewallControllerQuarantine:
    @patch("subprocess.run")
    def test_quarantine_ip_inserts_drop_rule(self, mock_run):
        mock_run.side_effect = [
            _mock_success(),                              # chain creation
            _mock_success(),                               # jump rule check
            _mock_failure_result("no such rule"),           # -C check for existing DROP rule
            _mock_success(),                                # -I insert DROP rule
        ]
        controller = FirewallController(dry_run=False)
        controller.quarantine_ip("10.0.0.99")

        insert_call_args = mock_run.call_args_list[-1][0][0]
        assert "-I" in insert_call_args
        assert "10.0.0.99" in insert_call_args
        assert "DROP" in insert_call_args

    @patch("subprocess.run")
    def test_quarantine_rejects_invalid_ip(self, mock_run):
        mock_run.side_effect = [_mock_success(), _mock_success()]
        controller = FirewallController(dry_run=False)

        with pytest.raises(FirewallControllerError):
            controller.quarantine_ip("not-an-ip-address")

    @patch("subprocess.run")
    def test_duplicate_quarantine_is_skipped(self, mock_run):
        mock_run.side_effect = [
            _mock_success(),
            _mock_success(),
            _mock_success(),   # -C check succeeds meaning rule already exists
        ]
        controller = FirewallController(dry_run=False)
        controller.quarantine_ip("10.0.0.50")

        # should have stopped after the -C check, never called -I
        insert_calls = [c for c in mock_run.call_args_list if "-I" in c[0][0]]
        assert len(insert_calls) == 0

    def test_dry_run_never_calls_subprocess(self):
        with patch("subprocess.run") as mock_run:
            controller = FirewallController(dry_run=True)
            controller.quarantine_ip("10.0.0.77")
            mock_run.assert_not_called()


class TestFirewallControllerListQuarantinedIps:
    @patch("subprocess.run")
    def test_negated_rule_is_excluded(self, mock_run):
        # a negated source ("-s ! 10.0.0.0/24") means "everything except
        # this range" - it is not an IP we quarantined and must not show
        # up in the returned list
        fake_iptables_output = (
            "-N ZT_MQTT_QUARANTINE\n"
            "-A ZT_MQTT_QUARANTINE -s 192.168.1.100/32 -j DROP\n"
            "-A ZT_MQTT_QUARANTINE -s ! 10.0.0.0/24 -j DROP\n"
        )
        mock_run.side_effect = [
            _mock_success(),
            _mock_success(),
            subprocess.CompletedProcess([], returncode=0, stdout=fake_iptables_output, stderr=""),
        ]
        controller = FirewallController(dry_run=False)
        ips = controller.list_quarantined_ips()

        assert "192.168.1.100/32" in ips
        assert "10.0.0.0/24" not in ips
        assert len(ips) == 1

    @patch("subprocess.run")
    def test_valid_cidr_rules_are_included(self, mock_run):
        fake_iptables_output = (
            "-N ZT_MQTT_QUARANTINE\n"
            "-A ZT_MQTT_QUARANTINE -s 192.168.1.100/32 -j DROP\n"
            "-A ZT_MQTT_QUARANTINE -s 172.28.0.55/32 -j DROP\n"
        )
        mock_run.side_effect = [
            _mock_success(),
            _mock_success(),
            subprocess.CompletedProcess([], returncode=0, stdout=fake_iptables_output, stderr=""),
        ]
        controller = FirewallController(dry_run=False)
        ips = controller.list_quarantined_ips()

        assert ips == ["192.168.1.100/32", "172.28.0.55/32"]

    @patch("subprocess.run")
    def test_malformed_rule_line_does_not_crash(self, mock_run):
        # garbage after "-s" that isn't a valid address/CIDR should be
        # skipped, not raise or get silently treated as a real IP
        fake_iptables_output = (
            "-N ZT_MQTT_QUARANTINE\n"
            "-A ZT_MQTT_QUARANTINE -s not-an-ip -j DROP\n"
            "-A ZT_MQTT_QUARANTINE -s 10.0.0.5/32 -j DROP\n"
        )
        mock_run.side_effect = [
            _mock_success(),
            _mock_success(),
            subprocess.CompletedProcess([], returncode=0, stdout=fake_iptables_output, stderr=""),
        ]
        controller = FirewallController(dry_run=False)
        ips = controller.list_quarantined_ips()

        assert ips == ["10.0.0.5/32"]

    @patch("subprocess.run")
    def test_empty_chain_returns_empty_list(self, mock_run):
        mock_run.side_effect = [
            _mock_success(),
            _mock_success(),
            subprocess.CompletedProcess([], returncode=0, stdout="-N ZT_MQTT_QUARANTINE\n", stderr=""),
        ]
        controller = FirewallController(dry_run=False)
        assert controller.list_quarantined_ips() == []


class TestQuarantineLedger:
    def test_add_and_check_entry(self, tmp_path):
        ledger_path = str(tmp_path / "ledger.json")
        ledger = QuarantineLedger(ledger_path)

        assert not ledger.is_quarantined("10.0.0.1")
        ledger.add_entry("10.0.0.1", "dev-01", -0.42, {"mean_payload_length": 5.0})
        assert ledger.is_quarantined("10.0.0.1")

    def test_release_entry_marks_inactive(self, tmp_path):
        ledger_path = str(tmp_path / "ledger.json")
        ledger = QuarantineLedger(ledger_path)

        ledger.add_entry("10.0.0.2", "dev-02", -0.3, {})
        ledger.release_entry("10.0.0.2")

        assert not ledger.is_quarantined("10.0.0.2")

    def test_ledger_persists_across_instances(self, tmp_path):
        ledger_path = str(tmp_path / "ledger.json")
        ledger_a = QuarantineLedger(ledger_path)
        ledger_a.add_entry("10.0.0.3", "dev-03", -0.5, {})

        ledger_b = QuarantineLedger(ledger_path)
        assert ledger_b.is_quarantined("10.0.0.3")

    def test_expire_stale_entries(self, tmp_path):
        ledger_path = str(tmp_path / "ledger.json")
        ledger = QuarantineLedger(ledger_path)
        ledger.add_entry("10.0.0.4", "dev-04", -0.6, {})

        # force the entry to look old by rewriting its timestamp directly
        with open(ledger_path) as f:
            data = json.load(f)
        data["10.0.0.4"]["quarantined_at"] = 0  # epoch, guaranteed stale
        with open(ledger_path, "w") as f:
            json.dump(data, f)

        ledger_reloaded = QuarantineLedger(ledger_path)
        expired = ledger_reloaded.expire_stale_entries(max_age_seconds=1)

        assert "10.0.0.4" in expired
        assert not ledger_reloaded.is_quarantined("10.0.0.4")

    def test_release_nonexistent_entry_does_not_raise(self, tmp_path):
        ledger_path = str(tmp_path / "ledger.json")
        ledger = QuarantineLedger(ledger_path)
        ledger.release_entry("10.0.0.99")  # should log a warning, not throw
