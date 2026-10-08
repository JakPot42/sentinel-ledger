//! Rulesets and the reference safety layer, docs/SPEC.md section 5.

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Declared,
    Opaque,
}

#[derive(Debug, Clone)]
pub enum Rule {
    Clamp { id: String, field: String, min: i64, max: i64 },
    BlockWhen { id: String, input: String, op: String, value: i64 },
}

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub ruleset_id: String,
    pub kind: Kind,
    pub rules: Vec<Rule>,
}

/// What a safety layer says it did with one command.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// `None` when the command was blocked.
    pub applied: Option<Map<String, Value>>,
    pub outcome: String,
    pub rules_acted: Vec<String>,
}

impl Verdict {
    pub fn to_value(&self) -> Value {
        json!({
            "applied": match &self.applied {
                Some(m) => Value::Object(m.clone()),
                None => Value::Null,
            },
            "outcome": self.outcome,
            "rules_acted": self.rules_acted,
        })
    }

    /// Read a verdict supplied from outside (an opaque safety layer's report).
    pub fn from_value(v: &Value) -> Result<Verdict, String> {
        let outcome = v.get("outcome").and_then(Value::as_str).ok_or("verdict has no outcome")?;
        if !["unchanged", "changed", "blocked"].contains(&outcome) {
            return Err(format!("unknown outcome {outcome}"));
        }
        let applied = match v.get("applied") {
            Some(Value::Object(m)) => Some(m.clone()),
            Some(Value::Null) => None,
            _ => return Err("verdict applied must be an object or null".to_string()),
        };
        if applied.is_none() != (outcome == "blocked") {
            return Err("applied must be null exactly when the outcome is blocked".to_string());
        }
        let mut rules_acted = Vec::new();
        for r in v.get("rules_acted").and_then(Value::as_array).ok_or("verdict has no rules_acted")? {
            rules_acted.push(r.as_str().ok_or("rules_acted must hold rule ids")?.to_string());
        }
        Ok(Verdict { applied, outcome: outcome.to_string(), rules_acted })
    }
}

fn text(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("ruleset: missing string {key}"))
}

fn whole(v: &Value, key: &str) -> Result<i64, String> {
    v.get(key).and_then(Value::as_i64).ok_or_else(|| format!("ruleset: missing integer {key}"))
}

pub fn parse(bytes: &[u8]) -> Result<Ruleset, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("ruleset is not JSON: {e}"))?;
    let kind = match text(&v, "kind")?.as_str() {
        "declared" => Kind::Declared,
        "opaque" => Kind::Opaque,
        other => return Err(format!("ruleset: unknown kind {other}")),
    };
    let mut rules = Vec::new();
    for r in v.get("rules").and_then(Value::as_array).ok_or("ruleset: missing rules")? {
        let id = text(r, "id")?;
        match text(r, "type")?.as_str() {
            "clamp" => {
                let (min, max) = (whole(r, "min")?, whole(r, "max")?);
                if min > max {
                    return Err(format!("ruleset: rule {id} has min above max"));
                }
                rules.push(Rule::Clamp { id, field: text(r, "field")?, min, max });
            }
            "block_when" => {
                let op = text(r, "op")?;
                if !["lt", "le", "eq", "ge", "gt"].contains(&op.as_str()) {
                    return Err(format!("ruleset: rule {id} has unknown op {op}"));
                }
                rules.push(Rule::BlockWhen { id, input: text(r, "input")?, op, value: whole(r, "value")? });
            }
            other => return Err(format!("ruleset: rule {id} has unknown type {other}")),
        }
    }
    Ok(Ruleset { ruleset_id: text(&v, "ruleset_id")?, kind, rules })
}

fn compare(op: &str, left: i64, right: i64) -> bool {
    match op {
        "lt" => left < right,
        "le" => left <= right,
        "eq" => left == right,
        "ge" => left >= right,
        _ => left > right,
    }
}

/// Apply the rules in file order. A `block_when` that fires ends evaluation.
/// A `block_when` whose input is absent or not an integer fires: a missing safety
/// signal is treated as unsafe. A `clamp` whose field is absent does nothing.
pub fn evaluate(ruleset: &Ruleset, requested: &Map<String, Value>, inputs: &Map<String, Value>) -> Verdict {
    let mut applied = requested.clone();
    let mut rules_acted = Vec::new();
    for rule in &ruleset.rules {
        match rule {
            Rule::Clamp { id, field, min, max } => {
                if let Some(v) = applied.get(field).and_then(Value::as_i64) {
                    #[cfg(feature = "planted-bug-clamp-bound")]
                    let max = &(*max + 100);
                    let bounded = v.clamp(*min, *max);
                    if bounded != v {
                        applied.insert(field.clone(), json!(bounded));
                        rules_acted.push(id.clone());
                    }
                }
            }
            Rule::BlockWhen { id, input, op, value } => {
                let fires = match inputs.get(input).and_then(Value::as_i64) {
                    Some(v) => compare(op, v, *value),
                    None => true,
                };
                #[cfg(feature = "planted-bug-skip-block")]
                let fires = fires && false;
                if fires {
                    rules_acted.push(id.clone());
                    return Verdict { applied: None, outcome: "blocked".to_string(), rules_acted };
                }
            }
        }
    }
    let outcome = if rules_acted.is_empty() { "unchanged" } else { "changed" };
    Verdict { applied: Some(applied), outcome: outcome.to_string(), rules_acted }
}

#[cfg(test)]
#[cfg(not(any(feature = "planted-bug-clamp-bound", feature = "planted-bug-skip-block")))]
mod tests {
    use super::*;

    const DEMO: &str = r#"{"ruleset_id":"t","kind":"declared","rules":[
        {"id":"R1","type":"block_when","input":"light_curtain_clear","op":"eq","value":0},
        {"id":"R2","type":"clamp","field":"speed_mm_s","min":0,"max":1500}]}"#;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn inside_the_limits_is_unchanged() {
        let rs = parse(DEMO.as_bytes()).unwrap();
        let v = evaluate(&rs, &obj(json!({"speed_mm_s": 1500})), &obj(json!({"light_curtain_clear": 1})));
        assert_eq!(v.outcome, "unchanged");
        assert!(v.rules_acted.is_empty());
    }

    #[test]
    fn above_and_below_are_clamped_to_the_nearer_bound() {
        let rs = parse(DEMO.as_bytes()).unwrap();
        let clear = obj(json!({"light_curtain_clear": 1}));
        let high = evaluate(&rs, &obj(json!({"speed_mm_s": 1501})), &clear);
        assert_eq!(high.applied.unwrap()["speed_mm_s"], json!(1500));
        assert_eq!(high.rules_acted, vec!["R2"]);
        let low = evaluate(&rs, &obj(json!({"speed_mm_s": -1})), &clear);
        assert_eq!(low.applied.unwrap()["speed_mm_s"], json!(0));
    }

    #[test]
    fn a_broken_or_missing_light_curtain_blocks() {
        let rs = parse(DEMO.as_bytes()).unwrap();
        let req = obj(json!({"speed_mm_s": 100}));
        let broken = evaluate(&rs, &req, &obj(json!({"light_curtain_clear": 0})));
        assert_eq!((broken.outcome.as_str(), broken.applied.is_none()), ("blocked", true));
        assert_eq!(broken.rules_acted, vec!["R1"]);
        assert_eq!(evaluate(&rs, &req, &Map::new()).outcome, "blocked");
    }

    #[test]
    fn unknown_rule_types_are_refused() {
        assert!(parse(br#"{"ruleset_id":"t","kind":"declared","rules":[{"id":"x","type":"scale"}]}"#).is_err());
        assert!(parse(br#"{"ruleset_id":"t","kind":"maybe","rules":[]}"#).is_err());
    }
}
