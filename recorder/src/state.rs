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
            anchor_every: v.get("anchor_every").and_then(Value::as_i64).unwrap_or(0),
            safe_state_action,
            software,
        })
    }

    /// The part of the configuration every record reader needs, committed in the
    /// genesis record and again whenever the configuration changes.
    pub fn settings(&self) -> Value {
        json!({
            "heartbeat_seconds": self.heartbeat_seconds,
            "measure_every": self.measure_every,
            "safe_state_action": self.safe_state_action,
        })
    }
}
