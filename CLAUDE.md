# kensa-android -- Android Compliance Runner

Android compliance runner implementing NIST 800-53 control mapping for device
properties. Maps device state (AVB, SELinux, encryption, patches) to compliance
controls. Produces compliance hash for tameshi MasterSignature.with_compliance().
12 NIST control checks.

## Build & Test

```bash
cargo build   # build library
cargo test    # run tests
```

## API

```rust
use kensa_android::*;

// Individual control checks
let avb = check_avb_locked(props);          // CM-2: AVB verified boot
let enc = check_encryption(props);          // SC-28: Encryption at rest
let patch = check_patch_level(props, 90);   // SI-2: Patch freshness

// Full device assessment
let result = assess_device(props);
println!("passed: {}", result.overall_passed);
println!("hash:   {}", result.compliance_hash);
```

## NIST 800-53 Control Mapping

| Control | Name | Check |
|---------|------|-------|
| AC-3 | Access Enforcement | SELinux enforcing |
| AC-4 | Information Flow | Network policy |
| AC-11 | Device Lock | Screen lock timeout |
| CM-2 | Baseline Configuration | AVB verified boot (green) |
| CM-7 | Least Functionality | Debug mode disabled |
| IA-2 | Identification/Auth | Biometric/PIN configured |
| SC-7 | Boundary Protection | Firewall active |
| SC-28 | Protection at Rest | Encryption (FBE/FDE) |
| SI-2 | Flaw Remediation | Security patch age |

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `blake3` | 1 | Compliance hash computation |
| `chrono` | 0.4 | Patch date age calculation |
| `regex` | 1 | Property line parsing |
| `serde` | 1 | Serialization |

## Conventions

- Edition 2024, Rust 1.91.0+, MIT, clippy pedantic
- Release: codegen-units=1, lto=true, opt-level="z", strip=true
- Library crate only (no binary)
- Accepts both `key=value` and `[key]: [value]` (getprop) formats
