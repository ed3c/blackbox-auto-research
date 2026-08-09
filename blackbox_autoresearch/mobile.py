"""Mobile black-box domain contracts for iOS and Android targets."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any


class MobilePlatform(str, Enum):
    IOS_SIMULATOR = "ios-simulator"
    IOS_DEVICE = "ios-device"
    ANDROID_EMULATOR = "android-emulator"
    ANDROID_DEVICE = "android-device"


@dataclass(frozen=True)
class MobileCapability:
    platform: MobilePlatform
    ui_tree: bool
    screenshots: bool
    network_capture: bool
    crash_capture: bool
    app_state_snapshot: bool
    hardware_dependent: bool
    reset_strength: str


CAPABILITY_MATRIX = {
    MobilePlatform.IOS_SIMULATOR: MobileCapability(
        MobilePlatform.IOS_SIMULATOR, True, True, True, True, True, False, "strong-with-snapshot"
    ),
    MobilePlatform.IOS_DEVICE: MobileCapability(
        MobilePlatform.IOS_DEVICE, True, True, True, True, True, True, "qualified-best-effort"
    ),
    MobilePlatform.ANDROID_EMULATOR: MobileCapability(
        MobilePlatform.ANDROID_EMULATOR, True, True, True, True, True, False, "strong-with-snapshot"
    ),
    MobilePlatform.ANDROID_DEVICE: MobileCapability(
        MobilePlatform.ANDROID_DEVICE, True, True, True, True, True, True, "qualified-best-effort"
    ),
}


@dataclass(frozen=True)
class DeviceDescriptor:
    device_id: str
    platform: MobilePlatform
    os_version: str
    model: str
    capabilities: tuple[str, ...] = ()


@dataclass
class DeviceLease:
    device: DeviceDescriptor
    owner: str
    active: bool = True


class DeviceLeaseScheduler:
    """Minimal exclusive lease scheduler preventing cross-run device state sharing."""

    def __init__(self, devices: tuple[DeviceDescriptor, ...] | list[DeviceDescriptor]) -> None:
        self._devices = {device.device_id: device for device in devices}
        self._leases: dict[str, DeviceLease] = {}

    def acquire(self, owner: str, *, platform: MobilePlatform | None = None) -> DeviceLease:
        for device_id in sorted(self._devices):
            device = self._devices[device_id]
            if platform is not None and device.platform is not platform:
                continue
            if device_id not in self._leases or not self._leases[device_id].active:
                lease = DeviceLease(device, owner)
                self._leases[device_id] = lease
                return lease
        raise RuntimeError("no matching mobile device available")

    def release(self, lease: DeviceLease) -> None:
        current = self._leases.get(lease.device.device_id)
        if current is not lease or not lease.active:
            raise ValueError("lease is not active")
        lease.active = False


@dataclass(frozen=True)
class ResetQualification:
    platform: MobilePlatform
    passed: bool
    checks: tuple[str, ...]
    caveats: tuple[str, ...] = ()


def qualify_reset(
    platform: MobilePlatform,
    *,
    app_data_cleared: bool,
    keychain_or_keystore_checked: bool,
    permissions_reset: bool,
    process_restarted: bool,
) -> ResetQualification:
    checks = []
    if app_data_cleared:
        checks.append("app-data")
    if keychain_or_keystore_checked:
        checks.append("secure-storage")
    if permissions_reset:
        checks.append("permissions")
    if process_restarted:
        checks.append("process")
    passed = all((app_data_cleared, keychain_or_keystore_checked, permissions_reset, process_restarted))
    caveats: list[str] = []
    if platform in {MobilePlatform.IOS_DEVICE, MobilePlatform.ANDROID_DEVICE}:
        caveats.append("real-device reset is qualified rather than assumed deterministic")
    return ResetQualification(platform, passed, tuple(checks), tuple(caveats))


@dataclass(frozen=True)
class MobileEvidence:
    kind: str
    digest: str
    payload: Any


def capture_mobile_evidence(kind: str, payload: Any) -> MobileEvidence:
    allowed = {"ui-tree", "screenshot", "crash", "network", "app-state"}
    if kind not in allowed:
        raise ValueError(f"unsupported mobile evidence kind: {kind}")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return MobileEvidence(kind, "sha256:" + hashlib.sha256(raw).hexdigest(), payload)


def requires_human_gate(action: str, *, real_device: bool) -> bool:
    destructive = {
        "factory-reset",
        "erase-device",
        "purchase",
        "send-message",
        "publish",
        "grant-sensitive-permission",
    }
    return real_device and action in destructive
