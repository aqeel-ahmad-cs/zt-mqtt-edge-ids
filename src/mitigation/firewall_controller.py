"""
Interfaces with iptables to isolate a flagged IP at the kernel level.
Shells out to the `iptables` binary via subprocess rather than using a
python-iptables binding directly, because the CLI tool is what's actually
guaranteed present on every target gateway distro we're likely to deploy
on, and it's a lot easier to reason about failure modes when the command
that ran is exactly the command you'd type by hand to debug it.
"""

import ipaddress
import logging
import subprocess

logger = logging.getLogger(__name__)


class FirewallControllerError(Exception):
    pass


class FirewallController:
    def __init__(self, chain: str = "ZT_MQTT_QUARANTINE", table: str = "filter", dry_run: bool = False):
        self.chain = chain
        self.table = table
        self.dry_run = dry_run
        self._ensure_chain_exists()

    def _run_iptables(self, args: list) -> subprocess.CompletedProcess:
        command = ["iptables", "-t", self.table] + args

        if self.dry_run:
            logger.info("[dry-run] would execute: %s", " ".join(command))
            return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except FileNotFoundError as exc:
            raise FirewallControllerError(
                "iptables binary not found on PATH - is this running on a Linux host?"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallControllerError(f"iptables command timed out: {exc}") from exc

        if result.returncode != 0:
            raise FirewallControllerError(
                f"iptables command failed (rc={result.returncode}): {result.stderr.strip()}"
            )

        return result

    def _ensure_chain_exists(self):
        """
        Creates the dedicated quarantine chain if it doesn't already exist,
        and makes sure FORWARD actually jumps into it. Using our own named
        chain instead of writing directly into FORWARD keeps our rules
        cleanly separable from whatever else is already configured on the
        box, which matters a lot when you're not the only thing managing
        iptables on that host.
        """
        try:
            self._run_iptables(["-N", self.chain])
            logger.info("created iptables chain %s", self.chain)
        except FirewallControllerError as exc:
            if "Chain already exists" in str(exc):
                logger.debug("chain %s already exists, reusing it", self.chain)
            else:
                logger.error("failed to create quarantine chain: %s", exc)
                raise

        try:
            self._run_iptables(["-C", "FORWARD", "-j", self.chain])
        except FirewallControllerError:
            # -C (check) fails if the jump rule isn't present yet, which is
            # the expected case on first run - so we insert it here
            try:
                self._run_iptables(["-I", "FORWARD", "1", "-j", self.chain])
                logger.info("inserted jump rule FORWARD -> %s", self.chain)
            except FirewallControllerError as exc:
                logger.error("failed to insert jump rule into FORWARD chain: %s", exc)
                raise

    def _validate_ip(self, ip_address: str):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise FirewallControllerError(f"refusing to act on invalid IP address '{ip_address}'") from exc

    def quarantine_ip(self, ip_address: str):
        self._validate_ip(ip_address)

        try:
            self._run_iptables(["-C", self.chain, "-s", ip_address, "-j", "DROP"])
            logger.info("%s is already quarantined, skipping duplicate rule", ip_address)
            return
        except FirewallControllerError:
            pass  # not present yet - fall through and add it

        try:
            self._run_iptables(["-I", self.chain, "1", "-s", ip_address, "-j", "DROP"])
            logger.warning("QUARANTINED %s - DROP rule installed in chain %s", ip_address, self.chain)
        except FirewallControllerError as exc:
            logger.error("failed to quarantine %s: %s", ip_address, exc)
            raise

    def release_ip(self, ip_address: str):
        self._validate_ip(ip_address)

        try:
            self._run_iptables(["-D", self.chain, "-s", ip_address, "-j", "DROP"])
            logger.info("released quarantine for %s", ip_address)
        except FirewallControllerError as exc:
            # if the rule was never there, -D fails - that's not really an
            # error condition worth propagating, just log and move on
            logger.warning("could not remove DROP rule for %s (may not have existed): %s", ip_address, exc)

    def list_quarantined_ips(self) -> list:
        try:
            result = self._run_iptables(["-S", self.chain])
        except FirewallControllerError as exc:
            logger.error("failed to list quarantine chain rules: %s", exc)
            return []

        ips = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if "-s" not in parts:
                continue

            idx = parts.index("-s")
            if idx + 1 >= len(parts):
                continue

            candidate = parts[idx + 1]

            # a negated source ("-s ! 10.0.0.0/24") means "match anything
            # NOT this range" - that's not an address we quarantined, so
            # treating it as one would be wrong (and iptables even puts
            # the "!" as its own token before the address, which the old
            # naive parser didn't account for at all)
            if candidate == "!":
                continue
            if idx > 0 and parts[idx - 1] == "!":
                continue

            # confirm this token is actually a valid address/CIDR before
            # trusting it - iptables -S output isn't something we control,
            # and a malformed or unexpected token here shouldn't silently
            # end up treated as a real quarantined host
            try:
                ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                logger.debug("skipping unparseable -s value in rule: %r", candidate)
                continue

            ips.append(candidate)

        return ips
