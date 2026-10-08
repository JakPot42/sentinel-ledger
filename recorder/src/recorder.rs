//! The recorder, docs/SPEC.md sections 4 to 7.
//!
//! One rule matters more than the rest: a command is sent to the actuator only after
//! its record has been appended to the journal and flushed to disk. `command()` is the
//! only function that forwards a command, and it does so after `write()` returned Ok.
//!
//! Every record, of every kind, is forwarded to the actuator-side gate with its number
//! and hash, so the gate can hold the head of the chain. The recorder never touches the
//! network: anchoring means writing a small statement file that another program sends on.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use logchain::hasher::{hash_leaf, to_hex};
use logchain::journal::{DataPaths, append_entry, load_state, read_entries};
use serde_json::{Map, Value, json};

use crate::canonical::canonical;
use crate::rules::{self, Kind, Ruleset, Verdict};
use crate::state::{Component, Config, State, sha256_hex};

pub const SCHEMA: &str = "sentinel-ledger/record/0";
pub const ANCHOR_SCHEMA: &str = "sentinel-ledger/anchor/0";
const AT_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// Why an operation did not complete.
#[derive(Debug)]
pub enum Fail {
    /// The input was not acceptable. Nothing was recorded, nothing was forwarded, and
    /// the recorder carries on.
    Rejected(String),
    /// The recorder could not do its job. It is now in the safe state until restarted.
    Fault(String),
}

/// The recorder's clock. `Fixed` exists so demo journals are reproducible: it starts at
/// a given time and moves one second forward after every record.
pub enum Clock {
    System,
    Fixed(DateTime<Utc>),
}

impl Clock {
    fn now(&self) -> DateTime<Utc> {
        match self {
            Clock::System => Utc::now(),
            Clock::Fixed(t) => *t,
        }
    }
}

pub fn parse_at(text: &str) -> Result<DateTime<Utc>, String> {
    NaiveDateTime::parse_from_str(text, AT_FORMAT)
        .map(|n| n.and_utc())
        .map_err(|_| format!("{text} is not a time of the form 2026-10-01T08:00:00Z"))
}

pub struct Recorder {
    paths: DataPaths,
    data_dir: PathBuf,
    installed: PathBuf,
    /// The wire to the actuator-side gate: one JSON message per line.
    link: PathBuf,
    /// The leaf hash of record 0. It names this journal in anchor statements.
    journal_id: String,
    config: Config,
    state: State,
    /// `state.in_force()`, kept beside it so every command record can name it.
    in_force: String,
    ruleset: Ruleset,
    n: usize,
    prev: String,
    last_at: Option<DateTime<Utc>>,
    clock: Clock,
    commands_since_measure: i64,
    pub fault: Option<String>,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Write a file and flush it to disk before returning.
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn object(v: Option<&Value>, what: &str) -> Result<Map<String, Value>, Fail> {
    match v {
        Some(Value::Object(m)) => Ok(m.clone()),
        _ => Err(Fail::Rejected(format!("{what} must be a JSON object"))),
    }
}

impl Recorder {
    /// Open a data directory. A new directory gets a genesis record. An existing one is
    /// replayed to find the state in force. Either way a `recorder_start` record is
    /// written and the installed files are measured before any command is accepted.
    pub fn open(data_dir: &Path, installed: &Path, link: &Path, clock: Clock) -> Result<Recorder, String> {
        for dir in ["", "rulesets", "decisions", "anchors"].map(|d| data_dir.join(d)) {
            fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let paths = DataPaths::from_dir(data_dir);
        let config_bytes = read(&installed.join("config.json"))?;
        let config = Config::parse(&config_bytes)?;
        let entries = read_entries(&paths.journal).map_err(|e| e.to_string())?;

        let mut rec = Recorder {
            paths,
            data_dir: data_dir.to_path_buf(),
            installed: installed.to_path_buf(),
            link: link.to_path_buf(),
            journal_id: String::new(),
            config,
            state: State { config_sha256: String::new(), ruleset_sha256: String::new(), software: BTreeMap::new() },
            in_force: String::new(),
            ruleset: Ruleset { ruleset_id: String::new(), kind: Kind::Opaque, rules: Vec::new() },
            n: 0,
            prev: String::new(),
            last_at: None,
            clock,
            commands_since_measure: 0,
            fault: None,
        };

        if entries.is_empty() {
            let ruleset_bytes = read(&installed.join("ruleset.json"))?;
            rec.ruleset = rules::parse(&ruleset_bytes)?;
            rec.state.config_sha256 = sha256_hex(&config_bytes);
            rec.state.ruleset_sha256 = sha256_hex(&ruleset_bytes);
            for s in rec.config.software.clone() {
                let sha256 = sha256_hex(&read(&installed.join(&s.file))?);
                rec.state.software.insert(s.name, Component { version: s.version, sha256 });
            }
            rec.archive_ruleset(&ruleset_bytes)?;
            rec.in_force = rec.state.in_force();
            let mut fields = Map::new();
            fields.insert("machine".into(), json!(rec.config.machine));
            fields.insert("state".into(), rec.state.to_value());
            fields.insert("settings".into(), rec.config.settings());
            rec.append("genesis", fields)?;
            rec.append("recorder_start", Map::new())?;
        } else {
            // Replay our own journal to recover the state in force.
            for entry in &entries {
                let r: Value = serde_json::from_str(&entry.raw).map_err(|e| format!("journal record: {e}"))?;
                match r["kind"].as_str() {
                    Some("genesis") => rec.state = State::from_value(&r["state"])?,
                    Some("intervention_declared") => {
                        rec.state.set(r["target"].as_str().unwrap_or(""), &r["new"])?
                    }
                    Some("intervention_detected") => {
                        for change in r["changes"].as_array().ok_or("journal record: no changes")? {
                            rec.state.set(change["target"].as_str().unwrap_or(""), &change["measured"])?;
                        }
                    }
                    _ => {}
                }
                rec.last_at = Some(parse_at(r["at"].as_str().unwrap_or(""))?);
            }
            rec.n = entries.len();
            rec.journal_id = entries[0].hash.clone();
            rec.prev = entries[entries.len() - 1].hash.clone();
            rec.in_force = rec.state.in_force();
            let archived = data_dir.join("rulesets").join(format!("{}.json", rec.state.ruleset_sha256));
            rec.ruleset = rules::parse(&read(&archived)?)?;
            rec.append("recorder_start", Map::new())?;
            rec.measure()?;
        }
        Ok(rec)
    }

    fn archive_ruleset(&self, bytes: &[u8]) -> Result<(), String> {
        let path = self.data_dir.join("rulesets").join(format!("{}.json", sha256_hex(bytes)));
        if path.exists() { Ok(()) } else { write_synced(&path, bytes) }
    }

    /// Step 3 of section 4: the record's text, its leaf hash and its time.
    fn build(&self, kind: &str, mut fields: Map<String, Value>) -> Result<(String, String, DateTime<Utc>), String> {
        let at = self.clock.now();
        if let Some(last) = self.last_at {
            if at < last {
                return Err(format!("clock reads {at}, earlier than the last record at {last}"));
            }
        }
        fields.insert("schema".into(), json!(SCHEMA));
        fields.insert("kind".into(), json!(kind));
        fields.insert("n".into(), json!(self.n));
        fields.insert("prev".into(), json!(self.prev));
        fields.insert("at".into(), json!(at.format(AT_FORMAT).to_string()));
        let raw = canonical(&Value::Object(fields))?;
        let hash = to_hex(hash_leaf(raw.as_bytes()));
        Ok((raw, hash, at))
    }

    /// Step 4 of section 4: append the record and flush it.
    fn write(&mut self, raw: &str, hash: &str, at: DateTime<Utc>) -> Result<(), String> {
        let entry = append_entry(raw, &self.paths.journal, &self.paths.state).map_err(|e| e.to_string())?;
        // LogChain's append does not flush. The record is not "written" for the
        // purposes of section 4 until this returns.
        OpenOptions::new()
            .append(true)
            .open(&self.paths.journal)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("cannot flush the journal: {e}"))?;
        if entry.hash != hash {
            return Err("the journal stored a different hash from the one computed".to_string());
        }
        if self.n == 0 {
            self.journal_id = entry.hash.clone();
        }
        self.prev = entry.hash;
        self.n += 1;
        self.last_at = Some(at);
        if let Clock::Fixed(t) = &mut self.clock {
            *t = at + Duration::seconds(1);
        }
        Ok(())
    }

    fn to_gate(&self, message: Value) -> Result<(), String> {
        let line = canonical(&message)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.link)
            .map_err(|e| format!("link to the actuator gate: {e}"))?;
        writeln!(f, "{line}").map_err(|e| format!("link to the actuator gate: {e}"))
    }

    /// Step 5 of section 4, and section 4.2: hand a record to the actuator-side gate
    /// with its number and hash. For a command record this is the forwarding itself:
    /// the gate takes the action from the record.
    fn forward(&self, n: usize, hash: &str, raw: &str) -> Result<(), String> {
        self.to_gate(json!({"type": "record", "n": n, "hash": hash, "record": raw}))
    }

    /// Build, write, then forward a record that is not a command.
    fn append(&mut self, kind: &str, fields: Map<String, Value>) -> Result<(), String> {
        let n = self.n;
        let (raw, hash, at) = self.build(kind, fields)?;
        self.write(&raw, &hash, at)?;
        self.forward(n, &hash, &raw)?;
        self.anchor(false)
    }

    /// Section 7.5: every `anchor_every` records, and at an orderly stop, write a
    /// statement of the root. Another program delivers it to a witness or a
    /// timestamping authority. Nothing here waits on a network.
    fn anchor(&self, always: bool) -> Result<(), String> {
        let every = self.config.anchor_every;
        if every <= 0 || !(always || self.n as i64 % every == 0) {
            return Ok(());
        }
        let state = load_state(&self.paths.state).map_err(|e| e.to_string())?;
        let statement = json!({
            "schema": ANCHOR_SCHEMA,
            "journal_id": self.journal_id,
            "entry_count": state.entry_count,
            "root": state.merkle_root,
            "last_at": self.last_at.map(|t| t.format(AT_FORMAT).to_string()),
        });
        let path = self.data_dir.join("anchors").join(format!("{:08}.json", state.entry_count));
        write_synced(&path, canonical(&statement)?.as_bytes())
    }

    /// Enter the safe state: note why, try to record it, send the safe-state action.
    fn enter_fault(&mut self, step: &str, detail: String) -> Fail {
        self.fault = Some(detail.clone());
        let mut fields = Map::new();
        fields.insert("step".into(), json!(step));
        fields.insert("detail".into(), json!(detail));
        let _ = self.append("recorder_fault", fields);
        let _ = self.to_gate(json!({"type": "safe_state", "why": "recorder_fault"}));
        Fail::Fault(detail)
    }

    /// Section 4, steps 1 to 5, for one command. Returns the record number and outcome.
    pub fn command(&mut self, op: &Value) -> Result<(usize, String), Fail> {
        if let Some(why) = self.fault.clone() {
            let _ = self.to_gate(json!({"type": "safe_state", "why": "recorder_fault"}));
            return Err(Fail::Fault(why));
        }
        let requested = object(op.get("requested"), "requested")?;
        let inputs = match op.get("safety_inputs") {
            None => Map::new(),
            some => object(some, "safety_inputs")?,
        };
        for (what, map) in [("requested", &requested), ("safety_inputs", &inputs)] {
            if let Err(e) = canonical(&Value::Object(map.clone())) {
                return Err(Fail::Rejected(format!("{what}: {e}")));
            }
        }

        // Step 2: what the safety layer says. For a declared ruleset the reference
        // safety layer in rules.rs answers, unless the caller supplies a report.
        let said = op.get("safety_layer_says");
        let verdict = match (&self.ruleset.kind, said) {
            (_, Some(v)) => Verdict::from_value(v).map_err(|e| self.enter_fault("safety_verdict", e))?,
            (Kind::Declared, None) => rules::evaluate(&self.ruleset, &requested, &inputs),
            (Kind::Opaque, None) => {
                return Err(self.enter_fault("safety_verdict", "the safety layer gave no verdict".to_string()));
            }
        };

        // Step 3: the record.
        let report = verdict.to_value();
        let mut fields = Map::new();
        fields.insert("requested".into(), Value::Object(requested));
        fields.insert("safety_inputs".into(), Value::Object(inputs));
        fields.insert("applied".into(), report["applied"].clone());
        fields.insert("outcome".into(), report["outcome"].clone());
        fields.insert("rules_acted".into(), report["rules_acted"].clone());
        fields.insert("reported".into(), report.clone());
        fields.insert("in_force".into(), json!(self.in_force));
        if let Some(decision) = op.get("decision") {
            let text = canonical(decision).map_err(|e| Fail::Rejected(format!("decision: {e}")))?;
            let sha = sha256_hex(text.as_bytes());
            let path = self.data_dir.join("decisions").join(format!("{sha}.json"));
            write_synced(&path, text.as_bytes()).map_err(|e| self.enter_fault("decision_file", e))?;
            fields.insert("decision_sha256".into(), json!(sha));
            fields.insert("decision_bytes".into(), json!(text.len()));
        }

        let n = self.n;
        let (raw, hash, at) = match self.build("command", fields) {
            Ok(built) => built,
            Err(e) => return Err(self.enter_fault("build", e)),
        };

        #[cfg(any(feature = "planted-bug-forward-first", feature = "planted-bug-forward-and-ignore-failed-write"))]
        let _ = self.forward(n, &hash, &raw);

        // Step 4. If it fails, step 5 does not happen.
        if let Err(e) = self.write(&raw, &hash, at) {
            // The second planted bug: carry on as if the write had worked, keeping the
            // chain in memory, so the gate goes on seeing records that follow each other.
            #[cfg(feature = "planted-bug-forward-and-ignore-failed-write")]
            {
                let _ = e;
                self.prev = hash;
                self.n += 1;
                self.last_at = Some(at);
                if let Clock::Fixed(t) = &mut self.clock {
                    *t = at + Duration::seconds(1);
                }
                return Ok((n, verdict.outcome));
            }
            #[cfg(not(feature = "planted-bug-forward-and-ignore-failed-write"))]
            return Err(self.enter_fault("append", e));
        }

        // Step 5.
        #[cfg(not(any(feature = "planted-bug-forward-first", feature = "planted-bug-forward-and-ignore-failed-write")))]
        if let Err(e) = self.forward(n, &hash, &raw) {
            return Err(self.enter_fault("forward", e));
        }
        self.anchor(false).map_err(|e| self.enter_fault("anchor", e))?;

        self.commands_since_measure += 1;
        if self.commands_since_measure >= self.config.measure_every {
            self.measure().map_err(|e| self.enter_fault("measure", e))?;
        }
        Ok((n, verdict.outcome))
    }

    /// Section 6.2: hash the installed files and record any that differ from the state
    /// in force as an `intervention_detected`.
    pub fn measure(&mut self) -> Result<(), String> {
        self.commands_since_measure = 0;
        let mut changes = Vec::new();
        let mut new_state = self.state.clone();
        let mut new_config = None;
        let mut new_ruleset = None;

        let config_bytes = read(&self.installed.join("config.json"))?;
        let sha = sha256_hex(&config_bytes);
        if sha != self.state.config_sha256 {
            new_config = Some(Config::parse(&config_bytes)?);
            changes.push(json!({"target": "config", "expected": self.state.config_sha256, "measured": sha}));
            new_state.config_sha256 = sha;
        }
        let ruleset_bytes = read(&self.installed.join("ruleset.json"))?;
        let sha = sha256_hex(&ruleset_bytes);
        if sha != self.state.ruleset_sha256 {
            new_ruleset = Some(rules::parse(&ruleset_bytes)?);
            self.archive_ruleset(&ruleset_bytes)?;
            changes.push(json!({"target": "ruleset", "expected": self.state.ruleset_sha256, "measured": sha}));
            new_state.ruleset_sha256 = sha;
        }
        // The set of components is fixed at genesis. A detected change keeps the last
        // declared version string: nobody told the recorder a new one.
        for s in self.config.software.clone() {
            let Some(known) = self.state.software.get(&s.name).cloned() else { continue };
            let sha256 = sha256_hex(&read(&self.installed.join(&s.file))?);
            if sha256 != known.sha256 {
                let measured = Component { version: known.version.clone(), sha256 };
                changes.push(json!({
                    "target": format!("software:{}", s.name),
                    "expected": known.to_value(),
                    "measured": measured.to_value(),
                }));
                new_state.software.insert(s.name, measured);
            }
        }
        if changes.is_empty() {
            return Ok(());
        }

        let mut fields = Map::new();
        fields.insert("changes".into(), Value::Array(changes));
        if let Some(c) = &new_config {
            fields.insert("settings".into(), c.settings());
        }
        self.append("intervention_detected", fields)?;
        self.adopt(new_state, new_config, new_ruleset);
        Ok(())
    }

    fn adopt(&mut self, state: State, config: Option<Config>, ruleset: Option<Ruleset>) {
        self.state = state;
        if let Some(c) = config {
            self.config = c;
        }
        if let Some(r) = ruleset {
            self.ruleset = r;
        }
        #[cfg(not(feature = "planted-bug-stale-in-force"))]
        {
            self.in_force = self.state.in_force();
        }
    }

    /// Section 6.2: a change made through the recorder. The record is written first,
    /// then the file is installed.
    pub fn declare(&mut self, op: &Value) -> Result<usize, Fail> {
        if let Some(why) = self.fault.clone() {
            return Err(Fail::Fault(why));
        }
        let text = |key: &str| {
            op.get(key).and_then(Value::as_str).map(str::to_string).ok_or(Fail::Rejected(format!("declare needs {key}")))
        };
        let (target, operator, reference) = (text("target")?, text("operator")?, text("reference")?);
        let bytes = read(Path::new(&text("file")?)).map_err(Fail::Rejected)?;
        let sha = sha256_hex(&bytes);

        let mut new_state = self.state.clone();
        let (mut new_config, mut new_ruleset) = (None, None);
        let (old, new, install_to);
        if target == "ruleset" {
            new_ruleset = Some(rules::parse(&bytes).map_err(Fail::Rejected)?);
            old = json!(self.state.ruleset_sha256);
            new = json!(sha);
            install_to = self.installed.join("ruleset.json");
        } else if target == "config" {
            let c = Config::parse(&bytes).map_err(Fail::Rejected)?;
            let names = |c: &Config| c.software.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
            if names(&c) != names(&self.config) {
                return Err(Fail::Rejected("the set of software components is fixed at genesis".to_string()));
            }
            new_config = Some(c);
            old = json!(self.state.config_sha256);
            new = json!(sha);
            install_to = self.installed.join("config.json");
        } else if let Some(name) = target.strip_prefix("software:") {
            let known = self.state.software.get(name).ok_or(Fail::Rejected(format!("no component {name}")))?;
            let entry = self.config.software.iter().find(|s| s.name == name);
            let file = entry.ok_or(Fail::Rejected(format!("no component {name} in the configuration")))?;
            old = known.to_value();
            new = Component { version: text("version")?, sha256: sha }.to_value();
            install_to = self.installed.join(&file.file);
        } else {
            return Err(Fail::Rejected(format!("unknown target {target}")));
        }
        new_state.set(&target, &new).map_err(Fail::Rejected)?;

        let mut fields = Map::new();
        fields.insert("target".into(), json!(target));
        fields.insert("old".into(), old);
        fields.insert("new".into(), new);
        fields.insert("operator".into(), json!(operator));
        fields.insert("reference".into(), json!(reference));
        // Reserved for a signature over the change. Not checked in this build.
        fields.insert("authorisation".into(), Value::Null);
        if let Some(c) = &new_config {
            fields.insert("settings".into(), c.settings());
        }

        let n = self.n;
        if target == "ruleset" {
            self.archive_ruleset(&bytes).map_err(|e| self.enter_fault("archive", e))?;
        }
        self.append("intervention_declared", fields).map_err(|e| self.enter_fault("append", e))?;
        write_synced(&install_to, &bytes).map_err(|e| self.enter_fault("install", e))?;
        self.adopt(new_state, new_config, new_ruleset);
        Ok(n)
    }

    /// Move the fixed clock forward, writing a heartbeat each time
    /// `heartbeat_seconds` pass with no record. Does nothing with the system clock:
    /// this build has no timer, see the limits in the specification.
    pub fn tick(&mut self, seconds: i64) -> Result<usize, Fail> {
        if self.fault.is_some() {
            return Ok(0);
        }
        let Clock::Fixed(now) = self.clock else { return Ok(0) };
        let target = now + Duration::seconds(seconds);
        let mut written = 0;
        #[cfg(not(feature = "planted-bug-no-heartbeat"))]
        while let Some(last) = self.last_at {
            let due = last + Duration::seconds(self.config.heartbeat_seconds);
            if due > target {
                break;
            }
            self.clock = Clock::Fixed(due);
            self.append("heartbeat", Map::new()).map_err(|e| self.enter_fault("append", e))?;
            written += 1;
        }
        if let Clock::Fixed(t) = &mut self.clock {
            if target > *t {
                *t = target;
            }
        }
        Ok(written)
    }

    /// A clean shutdown. Returns the root and the number of records.
    pub fn stop(&mut self) -> Result<(Option<String>, usize), String> {
        self.append("recorder_stop", Map::new())?;
        self.anchor(true)?;
        let state = load_state(&self.paths.state).map_err(|e| e.to_string())?;
        Ok((state.merkle_root, state.entry_count))
    }
}
