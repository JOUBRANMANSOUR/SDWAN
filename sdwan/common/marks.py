"""Collision-free v5 packet and conntrack mark layout.

The v4 low-byte transport ABI and state bits remain unchanged.  v5 adds hub
affinity and egress-mode fields above those bits; neither is matched by the
transport-slot rules.  nDPI writes only the transport slot and classification
state.  The Edge Agent writes/retains the target and egress fields as a local
route-actuation decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FlowMarkStage(str, Enum):
    UNKNOWN = "unknown"
    PROVISIONAL = "provisional"
    TERMINAL = "terminal"


class EgressMode(str, Enum):
    HUB_OVERLAY = "HUB_OVERLAY"
    DIRECT_INTERNET = "DIRECT_INTERNET"
    CLOUD_GATEWAY = "CLOUD_GATEWAY"


@dataclass(frozen=True)
class MarkLayout:
    """Bit allocation used for MARK and CONNMARK operations.

    * `0x000000ff`: v4 transport slot; MPLS=1, Broadband=2, LTE=3.
    * `0x00000100`: v4 terminal inspection state.
    * `0x00000200`: v4 provisional inspection state.
    * `0x00000400`: v4 emergency remapping state.
    * `0x00001000` / `0x00002000`: hub1 / hub2 target affinity.
    * `0x00004000` / `0x00008000`: direct Internet / Cloud Gateway egress.

    `HUB_OVERLAY` is encoded as zero in the egress field.  Save/restore uses
    `connection_mask` (`0x0000f7ff`) and never destroys unrelated marks.
    Linux policy routing uses only `route_mask` for its legacy 101/102/103
    route-slot rules, while hub-specific return-affinity rules use
    `route_mask | target_hub_mask`.
    """

    route_mask: int = 0x000000FF
    terminal_bit: int = 0x00000100
    provisional_bit: int = 0x00000200
    emergency_bit: int = 0x00000400
    target_hub_mask: int = 0x00003000
    hub1_bit: int = 0x00001000
    hub2_bit: int = 0x00002000
    egress_mask: int = 0x0000C000
    direct_internet_bit: int = 0x00004000
    cloud_gateway_bit: int = 0x00008000

    @property
    def state_mask(self) -> int:
        return self.terminal_bit | self.provisional_bit | self.emergency_bit

    @property
    def connection_mask(self) -> int:
        return self.route_mask | self.state_mask | self.target_hub_mask | self.egress_mask

    @property
    def affinity_mask(self) -> int:
        return self.route_mask | self.target_hub_mask | self.egress_mask

    def validate(self, path_marks: dict[str, int]) -> None:
        values = list(path_marks.values())
        if not values or len(values) != len(set(values)):
            raise ValueError("transport marks must be nonempty and unique")
        if any(value <= 0 or value & ~self.route_mask for value in values):
            raise ValueError("transport marks must fit entirely in the v4 low-byte route mask")
        bits = (
            self.terminal_bit, self.provisional_bit, self.emergency_bit,
            self.hub1_bit, self.hub2_bit, self.direct_internet_bit, self.cloud_gateway_bit,
        )
        if any(bit <= 0 or bit & (bit - 1) for bit in bits) or len(set(bits)) != len(bits):
            raise ValueError("state, hub, and egress values must be distinct single bits")
        fields = (self.route_mask, self.state_mask, self.target_hub_mask, self.egress_mask)
        if any(left & right for index, left in enumerate(fields) for right in fields[index + 1:]):
            raise ValueError("route, state, target-hub, and egress mark fields must not overlap")
        if self.target_hub_mask != self.hub1_bit | self.hub2_bit:
            raise ValueError("target_hub_mask must contain exactly hub1 and hub2 bits")
        if self.egress_mask != self.direct_internet_bit | self.cloud_gateway_bit:
            raise ValueError("egress_mask must contain exactly direct and cloud bits")

    def transport(self, mark: int) -> int:
        return mark & self.route_mask

    def stage(self, mark: int) -> FlowMarkStage:
        if mark & self.terminal_bit:
            return FlowMarkStage.TERMINAL
        if mark & self.provisional_bit:
            return FlowMarkStage.PROVISIONAL
        return FlowMarkStage.UNKNOWN

    def target_hub(self, mark: int) -> str | None:
        value = mark & self.target_hub_mask
        if value == self.hub1_bit:
            return "hub1"
        if value == self.hub2_bit:
            return "hub2"
        if value:
            raise ValueError("invalid multi-hub affinity mark")
        return None

    def egress_mode(self, mark: int) -> EgressMode:
        value = mark & self.egress_mask
        if value == 0:
            return EgressMode.HUB_OVERLAY
        if value == self.direct_internet_bit:
            return EgressMode.DIRECT_INTERNET
        if value == self.cloud_gateway_bit:
            return EgressMode.CLOUD_GATEWAY
        raise ValueError("invalid multi-egress mark")

    def encode(
        self,
        transport_mark: int,
        stage: FlowMarkStage = FlowMarkStage.UNKNOWN,
        *,
        emergency: bool = False,
        hub: str | None = None,
        egress: EgressMode = EgressMode.HUB_OVERLAY,
    ) -> int:
        if transport_mark <= 0 or transport_mark & ~self.route_mask:
            raise ValueError("transport mark is outside the v4 route mask")
        value = transport_mark
        if stage is FlowMarkStage.TERMINAL:
            value |= self.terminal_bit
        elif stage is FlowMarkStage.PROVISIONAL:
            value |= self.provisional_bit
        if emergency:
            value |= self.emergency_bit
        if hub == "hub1":
            value |= self.hub1_bit
        elif hub == "hub2":
            value |= self.hub2_bit
        elif hub is not None:
            raise ValueError("hub must be hub1, hub2, or None")
        if egress is EgressMode.DIRECT_INTERNET:
            value |= self.direct_internet_bit
        elif egress is EgressMode.CLOUD_GATEWAY:
            value |= self.cloud_gateway_bit
        return value
