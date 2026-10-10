//! The state in force, docs/SPEC.md section 6.1, and the settings read from the
//! configuration file.

use std::collections::BTreeMap;

use logchain::hasher::{hash_bytes, to_hex};
use serde_json::{Map, Value, json};

use crate::canonical::canonical;

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(hash_bytes(bytes))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub version: String,
    pub sha256: String,
}

impl Component {
    pub fn to_value(&self) -> Value {
        json!({"version": self.version, "sha256": self.sha256})
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct State {
    pub config_sha256: String,
    pub ruleset_sha256: String,
    pub software: BTreeMap<String, Component>,
}

impl State {
    pub fn to_value(&self) -> Value {
        let software: Map<String, Value> =
            self.software.iter().map(|(name, c)| (name.clone(), c.to_value())).collect();
        json!({
            "config_sha256": self.config_sha256,
            "ruleset_sha256": self.ruleset_sha256,
            "software": software,
        })
    }

    pub fn from_value(v: &Value) -> Result<State, String> {
        let field = |key: &str| {
            v.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("state lacks {key}"))
        };
        let mut software = BTreeMap::new();
        for (name, c) in v.get("software").and_then(Value::as_object).ok_or("state lacks software")? {
            software.insert(name.clone(), component_from(c)?);
        }
        Ok(State { config_sha256: field("config_sha256")?, ruleset_sha256: field("ruleset_sha256")?, software })
    }

    /// The `in_force` value: SHA-256 of the canonical form of the state.
    pub fn in_force(&self) -> String {
        let text = canonical(&self.to_value()).expect("state holds only strings");
        sha256_hex(text.as_bytes())
    }

    /// Apply one change. `target` is `ruleset`, `config` or `software:<name>`.
    pub fn set(&mut self, target: &str, new: &Value) -> Result<(), String> {
        if target == "ruleset" {
            self.ruleset_sha256 = new.as_str().ok_or("ruleset value must be a hash")?.to_string();
        } else if target == "config" {
            self.config_sha256 = new.as_str().ok_or("config value must be a hash")?.to_string();
        } else if let Some(name) = target.strip_prefix("software:") {
            self.software.insert(name.to_string(), component_from(new)?);
        } else {
            return Err(format!("unknown target {target}"));
        }
        Ok(())
    }
}

fn component_from(v: &Value) -> Result<Component, String> {
    let field = |key: &str| {
        v.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("component lacks {key}"))
    };
    Ok(Component { version: field("version")?, sha256: field("sha256")? })
}

/// One safety-critical component as the configuration file lists it.
#[derive(Debug, Clone)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: String,
    pub file: String,
}

/// The configuration file, parsed.
#[derive(Debug, Clone)]
pub struct Config {
    pub machine: String,
    pub heartbeat_seconds: i64,
    pub measure_every: i64,
    /// Write an anchor statement every this many records. 0 or absent: never.
    pub anchor_every: i64,
    /// Largest magnitude accepted when a ROS Twist is converted to integers:
    /// (linear, in mm/s; angular, in mrad/s). Absent when the machine takes no Twist.
    pub twist_limits: Option<(i64, i64)>,
    /// The Ed25519 public key records must be signed with, 64 hexadecimal characters.
    pub recorder_public_key: String,
    /// The actuator-side gate's deadman: with no valid record for this many seconds, the
    /// gate sends the safe state. Absent: the gate has no deadman (the file demo, where
    /// the gate reads a file after the fact and has no clock to run one against).
    pub gate_deadman_seconds: Option<i64>,
    /// The gate's limit on a command's age: a command received by the recorder more than
    /// this many milliseconds before it reaches the gate is not carried out. Absent: no
    /// limit (the file demo, whose gate has no clock).
    pub gate_max_command_age_ms: Option<i64>,
    pub safe_state_action: Value,
    pub software: Vec<SoftwareEntry>,
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Config, String> {
        let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("config is not JSON: {e}"))?;
        let text = |v: &Value, key: &str| {
            v.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("config lacks {key}"))
        };
        let whole = |key: &str| match v.get(key).and_then(Value::as_i64) {
            Some(i) if i > 0 => Ok(i),
            _ => Err(format!("config needs a positive integer {key}")),
        };
        let safe_state_action = v.get("safe_state_action").cloned().ok_or("config lacks safe_state_action")?;
        if !safe_state_action.is_object() || canonical(&safe_state_action).is_err() {
            return Err("safe_state_action must be an object of integers and strings".to_string());
        }
        let mut software = Vec::new();
        for s in v.get("software").and_then(Value::as_array).ok_or("config lacks software")? {
            software.push(SoftwareEntry {
                name: text(s, "name")?,
                version: text(s, "version")?,
                file: text(s, "file")?,
            });
        }
        Ok(Config {
            machine: text(&v, "machine")?,
            heartbeat_seconds: whole("heartbeat_seconds")?,
            measure_every: whole("measure_every")?,
            recorder_public_key: match v.get("recorder_public_key").and_then(Value::as_str) {
                Some(k) if k.len() == 64 && k.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) => k.to_string(),
                _ => return Err("config needs recorder_public_key: 64 lowercase hexadecimal characters".to_string()),
            },
            anchor_every: v.get("anchor_every").and_then(Value::as_i64).unwrap_or(0),
            gate_deadman_seconds: match v.get("gate_deadman_seconds") {
                None => None,
                Some(d) => match d.as_i64() {
                    Some(i) if i > 0 => Some(i),
                    _ => return Err("gate_deadman_seconds must be a positive integer".to_string()),
                },
            },
            gate_max_command_age_ms: match v.get("gate_max_command_age_ms") {
                None => None,
                Some(d) => match d.as_i64() {
                    Some(i) if i > 0 => Some(i),
                    _ => return Err("gate_max_command_age_ms must be a positive integer".to_string()),
                },
            },
            twist_limits: match v.get("twist_limits") {
                None => None,
                Some(t) => match (t.get("linear_mm_s").and_then(Value::as_i64), t.get("angular_mrad_s").and_then(Value::as_i64)) {
                    (Some(l), Some(a)) if l > 0 && a > 0 => Some((l, a)),
                    _ => return Err("twist_limits needs positive integers linear_mm_s and angular_mrad_s".to_string()),
                },
            },
            safe_state_action,
            software,
        })
    }

    /// The part of the configuration every record reader needs, committed in the
    /// genesis record and again whenever the configuration changes.
    pub fn settings(&self) -> Value {
        let mut settings = json!({
            "heartbeat_seconds": self.heartbeat_seconds,
            "measure_every": self.measure_every,
            "recorder_public_key": self.recorder_public_key,
            "safe_state_action": self.safe_state_action,
        });
        if let Some(seconds) = self.gate_deadman_seconds {
            settings["gate_deadman_seconds"] = json!(seconds);
        }
        if let Some(ms) = self.gate_max_command_age_ms {
            settings["gate_max_command_age_ms"] = json!(ms);
        }
        settings
    }
}
