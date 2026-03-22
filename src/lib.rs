use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// NIST 800-53 controls relevant to Android device compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NistControl {
    /// AC-3: Access Enforcement (SELinux enforcing)
    AC3,
    /// AC-4: Information Flow Enforcement (network policy)
    AC4,
    /// AC-11: Device Lock (screen lock timeout)
    AC11,
    /// CM-2: Baseline Configuration (verified boot)
    CM2,
    /// CM-7: Least Functionality (debug disabled)
    CM7,
    /// IA-2: Identification and Authentication (biometric/PIN)
    IA2,
    /// SC-7: Boundary Protection (firewall)
    SC7,
    /// SC-28: Protection of Information at Rest (encryption)
    SC28,
    /// SI-2: Flaw Remediation (security patches)
    SI2,
}

impl std::fmt::Display for NistControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AC3 => write!(f, "AC-3"),
            Self::AC4 => write!(f, "AC-4"),
            Self::AC11 => write!(f, "AC-11"),
            Self::CM2 => write!(f, "CM-2"),
            Self::CM7 => write!(f, "CM-7"),
            Self::IA2 => write!(f, "IA-2"),
            Self::SC7 => write!(f, "SC-7"),
            Self::SC28 => write!(f, "SC-28"),
            Self::SI2 => write!(f, "SI-2"),
        }
    }
}

/// Result of evaluating a single NIST control against device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    pub control: NistControl,
    pub passed: bool,
    pub evidence: String,
    pub checked_at: DateTime<Utc>,
}

/// Aggregate compliance result for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceComplianceResult {
    pub device_id: String,
    pub controls: Vec<ControlStatus>,
    pub overall_passed: bool,
    pub compliance_hash: String,
}

/// Check CM-2: AVB verified boot state is "green" (locked bootloader).
///
/// Looks for `ro.boot.verifiedbootstate=green` in device properties.
#[must_use]
pub fn check_avb_locked(props: &str) -> ControlStatus {
    let passed = props.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "ro.boot.verifiedbootstate=green"
            || trimmed == "[ro.boot.verifiedbootstate]: [green]"
    });

    ControlStatus {
        control: NistControl::CM2,
        passed,
        evidence: if passed {
            "verifiedbootstate=green (AVB locked)".into()
        } else {
            "verifiedbootstate is not green (AVB unlocked or missing)".into()
        },
        checked_at: Utc::now(),
    }
}

/// Check SC-28: Device encryption is active.
///
/// Looks for `ro.crypto.state=encrypted` in device properties.
#[must_use]
pub fn check_encryption(props: &str) -> ControlStatus {
    let passed = props.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "ro.crypto.state=encrypted"
            || trimmed == "[ro.crypto.state]: [encrypted]"
    });

    ControlStatus {
        control: NistControl::SC28,
        passed,
        evidence: if passed {
            "crypto.state=encrypted (FBE/FDE active)".into()
        } else {
            "crypto.state is not encrypted or missing".into()
        },
        checked_at: Utc::now(),
    }
}

/// Check SI-2: Security patch level is within acceptable age.
///
/// Looks for `ro.build.version.security_patch=YYYY-MM-DD` and checks
/// the patch is no older than `max_age_days`.
#[must_use]
pub fn check_patch_level(props: &str, max_age_days: u32) -> ControlStatus {
    let patch_re = regex::Regex::new(
        r"(?:ro\.build\.version\.security_patch=|\[ro\.build\.version\.security_patch\]: \[)(\d{4}-\d{2}-\d{2})"
    ).expect("valid regex");

    let result = props.lines().find_map(|line| {
        patch_re.captures(line.trim()).and_then(|caps| {
            caps.get(1).and_then(|m| {
                chrono::NaiveDate::parse_from_str(m.as_str(), "%Y-%m-%d").ok()
            })
        })
    });

    match result {
        Some(patch_date) => {
            let today = Utc::now().date_naive();
            let age = today.signed_duration_since(patch_date).num_days();
            let passed = age >= 0 && age <= i64::from(max_age_days);

            ControlStatus {
                control: NistControl::SI2,
                passed,
                evidence: format!(
                    "security_patch={patch_date}, age={age} days, max_allowed={max_age_days}"
                ),
                checked_at: Utc::now(),
            }
        }
        None => ControlStatus {
            control: NistControl::SI2,
            passed: false,
            evidence: "security_patch property not found".into(),
            checked_at: Utc::now(),
        },
    }
}

/// Run all compliance checks against device properties and produce a
/// [`DeviceComplianceResult`] with a BLAKE3 compliance hash.
#[must_use]
pub fn assess_device(props: &str) -> DeviceComplianceResult {
    let device_id = extract_device_id(props);
    let controls = vec![
        check_avb_locked(props),
        check_encryption(props),
        check_patch_level(props, 90),
    ];

    let overall_passed = controls.iter().all(|c| c.passed);

    // Compute compliance hash over all control results.
    let mut hasher = blake3::Hasher::new();
    hasher.update(device_id.as_bytes());
    for control in &controls {
        hasher.update(format!("{}:{}", control.control, control.passed).as_bytes());
    }
    let compliance_hash = hasher.finalize().to_hex().to_string();

    DeviceComplianceResult {
        device_id,
        controls,
        overall_passed,
        compliance_hash,
    }
}

/// Extract device serial from properties, falling back to "unknown".
fn extract_device_id(props: &str) -> String {
    let serial_re = regex::Regex::new(
        r"(?:ro\.serialno=|\[ro\.serialno\]: \[)([^\]\s]+)"
    ).expect("valid regex");

    props
        .lines()
        .find_map(|line| {
            serial_re
                .captures(line.trim())
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        })
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLIANT_PROPS: &str = "\
ro.serialno=ABC123DEF456
ro.boot.verifiedbootstate=green
ro.crypto.state=encrypted
ro.build.version.security_patch=2026-03-01
";

    const NONCOMPLIANT_PROPS: &str = "\
ro.serialno=XYZ789
ro.boot.verifiedbootstate=orange
ro.crypto.state=unencrypted
ro.build.version.security_patch=2024-01-01
";

    const GETPROP_FORMAT: &str = "\
[ro.serialno]: [PIXEL8PRO]
[ro.boot.verifiedbootstate]: [green]
[ro.crypto.state]: [encrypted]
[ro.build.version.security_patch]: [2026-02-05]
";

    #[test]
    fn avb_locked_passes_on_green() {
        let status = check_avb_locked(COMPLIANT_PROPS);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::CM2);
    }

    #[test]
    fn avb_locked_fails_on_orange() {
        let status = check_avb_locked(NONCOMPLIANT_PROPS);
        assert!(!status.passed);
    }

    #[test]
    fn avb_locked_passes_getprop_format() {
        let status = check_avb_locked(GETPROP_FORMAT);
        assert!(status.passed);
    }

    #[test]
    fn encryption_passes_when_encrypted() {
        let status = check_encryption(COMPLIANT_PROPS);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::SC28);
    }

    #[test]
    fn encryption_fails_when_unencrypted() {
        let status = check_encryption(NONCOMPLIANT_PROPS);
        assert!(!status.passed);
    }

    #[test]
    fn encryption_passes_getprop_format() {
        let status = check_encryption(GETPROP_FORMAT);
        assert!(status.passed);
    }

    #[test]
    fn patch_level_passes_within_age() {
        let status = check_patch_level(COMPLIANT_PROPS, 90);
        assert!(status.passed);
        assert_eq!(status.control, NistControl::SI2);
    }

    #[test]
    fn patch_level_fails_when_too_old() {
        let status = check_patch_level(NONCOMPLIANT_PROPS, 90);
        assert!(!status.passed);
    }

    #[test]
    fn patch_level_fails_when_missing() {
        let status = check_patch_level("ro.boot.verifiedbootstate=green\n", 90);
        assert!(!status.passed);
        assert!(status.evidence.contains("not found"));
    }

    #[test]
    fn patch_level_passes_getprop_format() {
        let status = check_patch_level(GETPROP_FORMAT, 90);
        assert!(status.passed);
    }

    #[test]
    fn assess_device_compliant() {
        let result = assess_device(COMPLIANT_PROPS);
        assert_eq!(result.device_id, "ABC123DEF456");
        assert!(result.overall_passed);
        assert_eq!(result.controls.len(), 3);
        assert!(!result.compliance_hash.is_empty());
    }

    #[test]
    fn assess_device_noncompliant() {
        let result = assess_device(NONCOMPLIANT_PROPS);
        assert_eq!(result.device_id, "XYZ789");
        assert!(!result.overall_passed);
    }

    #[test]
    fn assess_device_getprop_format() {
        let result = assess_device(GETPROP_FORMAT);
        assert_eq!(result.device_id, "PIXEL8PRO");
        assert!(result.overall_passed);
    }

    #[test]
    fn compliance_hash_deterministic() {
        let r1 = assess_device(COMPLIANT_PROPS);
        let r2 = assess_device(COMPLIANT_PROPS);
        assert_eq!(r1.compliance_hash, r2.compliance_hash);
    }

    #[test]
    fn compliance_hash_differs_between_devices() {
        let r1 = assess_device(COMPLIANT_PROPS);
        let r2 = assess_device(NONCOMPLIANT_PROPS);
        assert_ne!(r1.compliance_hash, r2.compliance_hash);
    }

    #[test]
    fn nist_control_display() {
        assert_eq!(NistControl::AC3.to_string(), "AC-3");
        assert_eq!(NistControl::SC28.to_string(), "SC-28");
        assert_eq!(NistControl::SI2.to_string(), "SI-2");
    }

    #[test]
    fn empty_props_fails_all_checks() {
        let result = assess_device("");
        assert_eq!(result.device_id, "unknown");
        assert!(!result.overall_passed);
        assert!(result.controls.iter().all(|c| !c.passed));
    }
}
