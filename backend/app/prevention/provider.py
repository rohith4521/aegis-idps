import abc
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class PreventionResult:
    success: bool
    provider: str
    action: str
    target: str
    status: str  # EXECUTED, FAILED, REVERTED
    message: str
    is_simulation: bool
    executed_at: datetime
    error: Optional[str] = None


class BasePreventionProvider(abc.ABC):
    @abc.abstractmethod
    def block_source(
        self,
        target: str,
        reason: str,
        duration_minutes: Optional[int],
        is_simulation: bool
    ) -> PreventionResult:
        """Execute a block action against a target address."""
        pass

    @abc.abstractmethod
    def unblock_source(
        self,
        target: str,
        reason: str,
        is_simulation: bool
    ) -> PreventionResult:
        """Execute an unblock action against a target address."""
        pass

    @abc.abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Report provider health and readiness."""
        pass


class MockPreventionProvider(BasePreventionProvider):
    """
    Default safe mock prevention provider.
    Executes and records auditable prevention decisions without
    making unauthorized host or network kernel packet filter modifications.
    """

    def block_source(
        self,
        target: str,
        reason: str,
        duration_minutes: Optional[int],
        is_simulation: bool
    ) -> PreventionResult:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        sim_text = "SIMULATED " if is_simulation else "MOCK "
        dur_text = f"for {duration_minutes} minutes" if duration_minutes else "indefinitely"
        message = (
            f"{sim_text}automatic block recorded for target {target} {dur_text}. "
            f"Provider is operating in safe mock mode (no real kernel rules altered)."
        )
        return PreventionResult(
            success=True,
            provider="mock",
            action="TEMPORARY_BLOCK" if duration_minutes else "PERMANENT_BLOCK",
            target=target,
            status="EXECUTED",
            message=message,
            is_simulation=is_simulation,
            executed_at=now,
            error=None
        )

    def unblock_source(
        self,
        target: str,
        reason: str,
        is_simulation: bool
    ) -> PreventionResult:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        sim_text = "SIMULATED " if is_simulation else "MOCK "
        message = (
            f"{sim_text}unblock decision executed for target {target}. "
            f"Reason: {reason}. Operating in safe mock mode."
        )
        return PreventionResult(
            success=True,
            provider="mock",
            action="UNBLOCK",
            target=target,
            status="EXECUTED",
            message=message,
            is_simulation=is_simulation,
            executed_at=now,
            error=None
        )

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "provider": "mock",
            "real_firewall_enabled": False,
            "readiness": True,
            "description": "Safe SOC Lab Mock Prevention Provider"
        }


class FirewallPreventionProvider(BasePreventionProvider):
    """
    Boundary adapter for future authorized lab firewall integrations (e.g. iptables/nftables).
    Intentionally disabled in this development phase to prevent accidental command execution.
    """

    def __init__(self, authorized_in_lab: bool = False):
        self.authorized_in_lab = authorized_in_lab

    def block_source(
        self,
        target: str,
        reason: str,
        duration_minutes: Optional[int],
        is_simulation: bool
    ) -> PreventionResult:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if not self.authorized_in_lab:
            return PreventionResult(
                success=False,
                provider="firewall",
                action="BLOCK_FAILED",
                target=target,
                status="FAILED",
                message="Real firewall provider is not authorized in this environment.",
                is_simulation=is_simulation,
                executed_at=now,
                error="FirewallProviderUnauthorized"
            )
        # Placeholder for isolated container iptables integration
        raise NotImplementedError("Real firewall actions are disabled in this phase.")

    def unblock_source(
        self,
        target: str,
        reason: str,
        is_simulation: bool
    ) -> PreventionResult:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return PreventionResult(
            success=False,
            provider="firewall",
            action="UNBLOCK_FAILED",
            target=target,
            status="FAILED",
            message="Real firewall provider is not authorized in this environment.",
            is_simulation=is_simulation,
            executed_at=now,
            error="FirewallProviderUnauthorized"
        )

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "disabled",
            "provider": "firewall",
            "real_firewall_enabled": False,
            "readiness": False,
            "description": "Real firewall provider is disabled for host safety."
        }
