# Mobile Integration

Issue: #22

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
platforms: [ios-simulator, ios-device, android-emulator, android-device]
```

## Agent task

Connect the capability/reset/evidence contracts to actual platform tooling and prove comparable task execution across virtual and physical devices.

## Required probes

- clean reset/reinstall behavior;
- Keychain/Keystore persistence behavior;
- permissions and secure-storage reset;
- UI tree + screenshot + app-state correlation;
- crash and network evidence;
- app build digest and device capability digest;
- destructive action human gate;
- simulator/emulator versus real-device differences.

## Privacy/safety

Never commit UDIDs, serial numbers, signing certificates, provisioning profiles, tokens, user data, or other device-identifying material. Hash/redact capability evidence where needed.

## Done

#22 closes only after at least one iOS and one Android real-device task plus their virtual-device counterparts produce replayable evidence and reset qualification.
