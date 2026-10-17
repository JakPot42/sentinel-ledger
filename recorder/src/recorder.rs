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
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use ed25519_dalek::SigningKey;
use logchain::hasher::{hash_leaf, to_hex};
use logchain::journal::{DataPaths, append_entry, load_state, read_entries};
use serde_json::{Map, Value, json};

use crate::canonical::canonical;
use crate::rules::{self, Kind, Ruleset, Verdict};
use crate::signing;
use crate::state::{Component, Config, State, sha256_hex};

pub const SCHEMA: &str = "sentinel-ledger/record/0";
pub const ANCHOR_SCHEMA: &str = "sentinel-ledger/anchor/0";
pub const GATE_RECEIPT_SCHEMA: &str = "sentinel-ledger/gate-receipt/0";
pub const FEEDBACK_SCHEMA: &str = "sentinel-ledger/actuator-feedback/0";
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

/// Where forwarded records go: the link to the actuator-side gate.
pub enum Link {
    /// One JSON message per line, appended to a file. The demo's link.
    File(PathBuf),
    /// Handed to a function, for example one that publishes on a ROS topic.
    Sink(Box<dyn Fn(&str) -> Result<(), String> + Send>),
}

pub struct Recorder {
    paths: DataPaths,
    data_dir: PathBuf,
    installed: PathBuf,
    /// The wire to the actuator-side gate: one JSON message at a time.
    link: Link,
    /// The leaf hash of record 0. It names this journal in anchor statements.
    journal_id: String,
    /// Signs every record. Its public half is in the configuration in force.
    key: SigningKey,
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
    /// Set by `stop()`. Nothing is written after the stop record.
    stopped: bool,
    /// For diagnosis only: called with the name of each step that touches the disk and
    /// how long it took. Changes nothing the recorder writes.
    pub timing: Option<Box<dyn Fn(&'static str, std::time::Duration) + Send>>,
    /// Where anchor statements go. `None`: this recorder writes and flushes each one
    /// itself before carrying on. `Some`: the statement's path and text are handed over
    /// and the recorder carries on at once; whoever took them writes them with
    /// `write_anchor`. The ROS node does this so that a slow disk does not hold the
    /// recorder up for an anchor. An anchor is evidence about records already written:
    /// nothing a record needs waits for it.
    pub anchor_out: Option<Box<dyn Fn(PathBuf, Vec<u8>) + Send>>,
    /// Time spent waiting for storage since the last record's time was taken.
    storage: StorageTime,
    /// Anchor statements that could not be written and have not yet been stated in an
    /// `anchor_failed` record: (the entry count the statement covered, why).
    anchor_failures: VecDeque<(usize, String)>,
    /// Test builds only: make the flush of one record slow. (kind, which one of that
    /// kind counting from 1, how long). Cannot be set in a normal build.
    slow_flush: Option<(String, usize, std::time::Duration)>,
    writes_of_kind: BTreeMap<String, usize>,
    /// The number of the last gate receipt written to the journal. A receipt with that
    /// number or a lower one is not written again.
    last_receipt_seq: Option<u64>,
    /// Command records forwarded by this process for which no receipt has come back yet.
    /// Only kept when the configuration names a gate key.
    awaiting_receipt: BTreeSet<usize>,
    /// The number of the last actuator feedback written to the journal.
    last_feedback_seq: Option<u64>,
    /// Command records forwarded by this process for which no feedback has come back yet.
    /// Only kept when the configuration names a feedback key.
    awaiting_feedback: BTreeSet<usize>,
}

/// Time spent in storage steps over one interval between records, on the monotonic clock.
#[derive(Default)]
struct StorageTime {
    total_ms: u128,
    /// The longest single step in the interval: (its name, the record it belonged to, how long).
    longest: Option<(&'static str, usize, u128)>,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Write a file and flush it to disk before returning.
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Write one anchor statement: to a temporary name, flushed, then renamed into place, so
/// a reader never finds half a statement under the statement's own name.
pub fn write_anchor(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    write_synced(&tmp, bytes)?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot write {}: {e}", path.display()))
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
    pub fn open(data_dir: &Path, installed: &Path, key_file: &Path, link: Link, clock: Clock) -> Result<Recorder, String> {
        for dir in ["", "rulesets", "decisions", "anchors"].map(|d| data_dir.join(d)) {
            fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let paths = DataPaths::from_dir(data_dir);
        let config_bytes = read(&installed.join("config.json"))?;
        let config = Config::parse(&config_bytes)?;
        let key = signing::load_key(key_file)?;
        if signing::public_hex(&key) != config.recorder_public_key {
            return Err("the key file is not the private half of recorder_public_key in the configuration".to_string());
        }
        let entries = read_entries(&paths.journal).map_err(|e| e.to_string())?;

        let mut rec = Recorder {
            paths,
            data_dir: data_dir.to_path_buf(),
            installed: installed.to_path_buf(),
            link,
            journal_id: String::new(),
            key,
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
            stopped: false,
            timing: None,
            anchor_out: None,
            storage: StorageTime::default(),
            anchor_failures: VecDeque::new(),
            slow_flush: None,
            writes_of_kind: BTreeMap::new(),
            last_receipt_seq: None,
            awaiting_receipt: BTreeSet::new(),
            last_feedback_seq: None,
            awaiting_feedback: BTreeSet::new(),
        };
        // A test build can be told to make one flush slow: SL_TEST_SLOW_FLUSH=kind:which:ms.
        #[cfg(feature = "test-slow-flush")]
        if let Ok(text) = std::env::var("SL_TEST_SLOW_FLUSH") {
            let parts: Vec<&str> = text.split(':').collect();
            if let (Some(kind), Some(Ok(which)), Some(Ok(ms))) =
                (parts.first(), parts.get(1).map(|p| p.parse::<usize>()), parts.get(2).map(|p| p.parse::<u64>()))
            {
                rec.slow_flush = Some((kind.to_string(), which, std::time::Duration::from_millis(ms)));
            }
        }

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
                    Some("gate_receipt") => rec.last_receipt_seq = r["receipt"]["seq"].as_u64(),
                    Some("actuator_feedback") => rec.last_feedback_seq = r["feedback"]["seq"].as_u64(),
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
    fn build(&self, kind: &str, fields: Map<String, Value>) -> Result<(String, String, DateTime<Utc>), String> {
        self.build_at(kind, fields, self.clock.now())
    }

    fn build_at(
        &self,
        kind: &str,
        mut fields: Map<String, Value>,
        at: DateTime<Utc>,
    ) -> Result<(String, String, DateTime<Utc>), String> {
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
        // The signature covers the canonical form of every other field. It then goes
        // into the record, so the leaf hash and the next record's `prev` cover it too.
        let unsigned = canonical(&Value::Object(fields.clone()))?;
        fields.insert("sig".into(), json!(signing::sign(&self.key, &unsigned)));
        let raw = canonical(&Value::Object(fields))?;
        let hash = to_hex(hash_leaf(raw.as_bytes()));
        Ok((raw, hash, at))
    }

    fn timed(&self, step: &'static str, started: std::time::Instant) {
        if let Some(report) = &self.timing {
            report(step, started.elapsed());
        }
    }

    /// A storage step has finished: add its time to this interval's total.
    fn note_stall(&mut self, step: &'static str, of_record: usize, started: Instant) {
        let took = started.elapsed().as_millis();
        self.storage.total_ms += took;
        if self.storage.longest.is_none_or(|(_, _, longest)| took > longest) {
            self.storage.longest = Some((step, of_record, took));
        }
    }

    /// Sections 7.2 and 8. Two things the recorder states about itself, each as a signed
    /// record, as soon as it can.
    ///
    /// A storage stall. The verifier calls it a gap when the times of two consecutive
    /// records, in whole seconds, differ by more than twice the heartbeat interval. This
    /// applies exactly that test, on the same clock and at the same resolution, to the
    /// last record's time and now. If it is a gap, and the time this recorder spent
    /// waiting for storage since the last record accounts for it by the verifier's own
    /// rule (the gap less the storage time is within the allowance), the next record is a
    /// `storage_stall` record carrying that storage time, measured on the monotonic
    /// clock. Because the test is the verifier's, a gap is never left unexplained for a
    /// difference in rounding between the two. Writing the record can itself be slow,
    /// which can leave another gap; at most three are written in one go.
    ///
    /// An anchor statement that could not be written: an `anchor_failed` record.
    fn report_stalls(&mut self) -> Result<(), String> {
        for _ in 0..3 {
            let Some(last) = self.last_at else { break };
            let now = self.clock.now();
            let gap = now.timestamp() - last.timestamp();
            let limit = 2 * self.config.heartbeat_seconds;
            let waited = self.storage.total_ms as i64;
            if !(gap > limit && waited > 0 && gap * 1000 - waited <= limit * 1000) {
                break;
            }
            let storage = std::mem::take(&mut self.storage);
            let (step, of_record, _) = storage.longest.unwrap_or(("journal_write", self.n.saturating_sub(1), 0));
            let mut fields = Map::new();
            fields.insert("step".into(), json!(step));
            fields.insert("of_record".into(), json!(of_record));
            fields.insert("stalled_ms".into(), json!(storage.total_ms as u64));
            let n = self.n;
            let (raw, hash, at) = self.build_at("storage_stall", fields, now)?;
            self.write("storage_stall", &raw, &hash, at)?;
            self.forward(n, &hash, &raw)?;
        }
        for _ in 0..3 {
            let Some((entry_count, detail)) = self.anchor_failures.pop_front() else { break };
            let mut fields = Map::new();
            fields.insert("entry_count".into(), json!(entry_count));
            fields.insert("detail".into(), json!(detail));
            let n = self.n;
            let (raw, hash, at) = self.build("anchor_failed", fields)?;
            self.write("anchor_failed", &raw, &hash, at)?;
            self.forward(n, &hash, &raw)?;
        }
        Ok(())
    }

    /// A record is about to be built. State anything pending first, then start a new
    /// interval: storage time from here on belongs to the gap after this record.
    fn begin_record(&mut self) -> Result<(), String> {
        self.report_stalls()?;
        self.storage = StorageTime::default();
        Ok(())
    }

    /// An anchor statement could not be written. Not a fault: the recorder carries on,
    /// and says so in the journal with its next record. `entry_count` is the number of
    /// records the lost statement covered.
    pub fn anchor_failed(&mut self, entry_count: usize, detail: String) {
        self.anchor_failures.push_back((entry_count, detail));
    }

    /// Write down anything the recorder has to state about itself and has not yet. The
    /// ROS node calls this from its heartbeat thread, so that an anchor failure reported
    /// by the anchor thread reaches the journal without waiting for the next command.
    pub fn record_pending(&mut self) -> Result<(), Fail> {
        if self.stopped || self.fault.is_some() {
            return Ok(());
        }
        self.report_stalls().map_err(|e| self.enter_fault("append", e))
    }

    /// Test builds only: make the flush of one record slow.
    #[cfg(any(test, feature = "test-slow-flush"))]
    pub fn slow_flush_for_test(&mut self, kind: &str, which: usize, how_long: std::time::Duration) {
        self.slow_flush = Some((kind.to_string(), which, how_long));
    }

    /// Step 4 of section 4: append the record and flush it.
    fn write(&mut self, kind: &str, raw: &str, hash: &str, at: DateTime<Utc>) -> Result<(), String> {
        let whole = Instant::now();
        let started = std::time::Instant::now();
        let entry = append_entry(raw, &self.paths.journal, &self.paths.state).map_err(|e| e.to_string())?;
        self.timed("journal_append", started);
        let started = std::time::Instant::now();
        let count = self.writes_of_kind.entry(kind.to_string()).or_insert(0);
        *count += 1;
        if let Some((slow_kind, which, how_long)) = &self.slow_flush {
            if slow_kind == kind && which == count {
                std::thread::sleep(*how_long);
            }
        }
        // LogChain's append does not flush. The record is not "written" for the
        // purposes of section 4 until this returns.
        OpenOptions::new()
            .append(true)
            .open(&self.paths.journal)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("cannot flush the journal: {e}"))?;
        self.timed("journal_fsync", started);
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
        self.note_stall("journal_write", self.n - 1, whole);
        Ok(())
    }

    fn to_gate(&self, message: Value) -> Result<(), String> {
        let line = canonical(&message)?;
        match &self.link {
            Link::File(path) => {
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("link to the actuator gate: {e}"))?;
                writeln!(f, "{line}").map_err(|e| format!("link to the actuator gate: {e}"))
            }
            Link::Sink(send) => send(&line),
        }
    }

    /// Step 5 of section 4, and section 4.2: hand a record to the actuator-side gate
    /// with its number and hash. For a command record this is the forwarding itself:
    /// the gate takes the action from the record.
    fn forward(&self, n: usize, hash: &str, raw: &str) -> Result<(), String> {
        self.to_gate(json!({"type": "record", "n": n, "hash": hash, "record": raw}))
    }

    /// Build, write, then forward a record that is not a command. Returns its number.
    fn append(&mut self, kind: &str, fields: Map<String, Value>) -> Result<usize, String> {
        self.begin_record()?;
        let n = self.n;
        let (raw, hash, at) = self.build(kind, fields)?;
        self.write(kind, &raw, &hash, at)?;
        self.forward(n, &hash, &raw)?;
        self.anchor(false)?;
        // Nothing is written after the stop record, so a stall in writing the stop
        // record itself, or a failure to write the last anchor, is never stated.
        if kind != "recorder_stop" {
            self.report_stalls()?;
        }
        Ok(n)
    }

    /// Section 7.5: every `anchor_every` records, and at an orderly stop, write a
    /// statement of the root. Another program delivers it to a witness or a
    /// timestamping authority. Nothing here waits on a network.
    fn anchor(&mut self, always: bool) -> Result<(), String> {
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
        let text = canonical(&statement)?;
        if let Some(hand_over) = &self.anchor_out {
            hand_over(path, text.into_bytes());
            return Ok(());
        }
        let started = Instant::now();
        let written = write_anchor(&path, text.as_bytes());
        self.timed("anchor_write_fsync", started);
        self.note_stall("anchor_write", self.n - 1, started);
        // An anchor that cannot be written does not stop the machine. It is stated in
        // the journal (`anchor_failed`), and the verifier reports it.
        if let Err(e) = written {
            self.anchor_failed(state.entry_count, e);
        }
        Ok(())
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
        if self.stopped {
            return Err(Fail::Rejected("the recorder has stopped".to_string()));
        }
        if let Some(why) = self.fault.clone() {
            let _ = self.to_gate(json!({"type": "safe_state", "why": "recorder_fault"}));
            return Err(Fail::Fault(why));
        }
        // When the command arrived, in milliseconds since 1970 on this recorder's clock.
        // The caller says when (the ROS node notes it as the message arrives); otherwise
        // it is now. The gate measures a command's age from this.
        let received_ms = match op.get("received_ms") {
            None => self.clock.now().timestamp_millis(),
            Some(v) => v.as_i64().ok_or(Fail::Rejected("received_ms must be an integer".to_string()))?,
        };
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
        fields.insert("received_ms".into(), json!(received_ms));
        if let Some(decision) = op.get("decision") {
            let text = canonical(decision).map_err(|e| Fail::Rejected(format!("decision: {e}")))?;
            let sha = sha256_hex(text.as_bytes());
            let path = self.data_dir.join("decisions").join(format!("{sha}.json"));
            let started = Instant::now();
            write_synced(&path, text.as_bytes()).map_err(|e| self.enter_fault("decision_file", e))?;
            self.note_stall("decision_file", self.n, started);
            fields.insert("decision_sha256".into(), json!(sha));
            fields.insert("decision_bytes".into(), json!(text.len()));
        }

        self.begin_record().map_err(|e| self.enter_fault("append", e))?;
        let n = self.n;
        let (raw, hash, at) = match self.build("command", fields) {
            Ok(built) => built,
            Err(e) => return Err(self.enter_fault("build", e)),
        };

        #[cfg(any(feature = "planted-bug-forward-first", feature = "planted-bug-forward-and-ignore-failed-write"))]
        let _ = self.forward(n, &hash, &raw);

        // Step 4. If it fails, step 5 does not happen.
        if let Err(e) = self.write("command", &raw, &hash, at) {
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
        if self.config.gate_public_key.is_some() {
            self.awaiting_receipt.insert(n);
        }
        if self.config.feedback_public_key.is_some() {
            self.awaiting_feedback.insert(n);
        }
        self.anchor(false).map_err(|e| self.enter_fault("anchor", e))?;
        // The command has gone to the gate. If writing it stalled, say so now.
        self.report_stalls().map_err(|e| self.enter_fault("append", e))?;

        self.commands_since_measure += 1;
        if self.commands_since_measure >= self.config.measure_every {
            self.measure().map_err(|e| self.enter_fault("measure", e))?;
        }
        Ok((n, verdict.outcome))
    }

    /// Section 6.2: hash the installed files and record any that differ from the state
    /// in force as an `intervention_detected`.
    pub fn measure(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        self.commands_since_measure = 0;
        let mut changes = Vec::new();
        let mut new_state = self.state.clone();
        let mut new_config = None;
        let mut new_ruleset = None;

        let config_bytes = read(&self.installed.join("config.json"))?;
        let sha = sha256_hex(&config_bytes);
        if sha != self.state.config_sha256 {
            let parsed = Config::parse(&config_bytes)?;
            if parsed.recorder_public_key != self.config.recorder_public_key {
                return Err("the installed configuration names a different recorder key; key rotation is not supported".to_string());
            }
            if parsed.gate_public_key != self.config.gate_public_key {
                return Err("the installed configuration names a different gate key; key rotation is not supported".to_string());
            }
            if parsed.feedback_public_key != self.config.feedback_public_key {
                return Err("the installed configuration names a different feedback key; key rotation is not supported".to_string());
            }
            new_config = Some(parsed);
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
        if self.stopped {
            return Err(Fail::Rejected("the recorder has stopped".to_string()));
        }
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
            if c.recorder_public_key != self.config.recorder_public_key
                || c.gate_public_key != self.config.gate_public_key
                || c.feedback_public_key != self.config.feedback_public_key
            {
                return Err(Fail::Rejected("key rotation is not supported".to_string()));
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
        let started = Instant::now();
        write_synced(&install_to, &bytes).map_err(|e| self.enter_fault("install", e))?;
        self.note_stall("install", n, started);
        self.report_stalls().map_err(|e| self.enter_fault("append", e))?;
        self.adopt(new_state, new_config, new_ruleset);
        Ok(n)
    }

    /// Move the fixed clock forward, writing a heartbeat each time
    /// `heartbeat_seconds` pass with no record. Does nothing with the system clock:
    /// this build has no timer, see the limits in the specification.
    pub fn tick(&mut self, seconds: i64) -> Result<usize, Fail> {
        if self.fault.is_some() || self.stopped {
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

    /// With the system clock: write a heartbeat if `heartbeat_seconds` have passed since
    /// the last record. Something outside must call this regularly; the ROS node does.
    pub fn heartbeat_if_due(&mut self) -> Result<bool, Fail> {
        let due = match self.last_at {
            Some(last) => self.clock.now() - last >= Duration::seconds(self.config.heartbeat_seconds),
            None => false,
        };
        if self.stopped || self.fault.is_some() || !due || cfg!(feature = "planted-bug-no-heartbeat") {
            return Ok(false);
        }
        self.append("heartbeat", Map::new()).map_err(|e| self.enter_fault("append", e))?;
        Ok(true)
    }

    /// Section 4.5: take a receipt the gate signed and write it into the journal as a
    /// record of its own. Returns the record's number and the receipt's.
    ///
    /// The recorder checks two things before it writes: that the receipt is signed with
    /// the gate key the configuration names, and that its number is higher than the last
    /// one written, so that a receipt sent twice, or made by another node, is not
    /// written. It does not judge what the receipt says. That is the verifier's work.
    pub fn gate_receipt(&mut self, receipt: &Value) -> Result<(usize, u64), Fail> {
        if self.stopped {
            return Err(Fail::Rejected("the recorder has stopped".to_string()));
        }
        if let Some(why) = self.fault.clone() {
            return Err(Fail::Fault(why));
        }
        let Some(gate_key) = self.config.gate_public_key.clone() else {
            return Err(Fail::Rejected("the configuration names no gate key".to_string()));
        };
        let fields = object(Some(receipt), "a receipt")?;
        if fields.get("schema").and_then(Value::as_str) != Some(GATE_RECEIPT_SCHEMA) {
            return Err(Fail::Rejected(format!("a receipt's schema must be {GATE_RECEIPT_SCHEMA}")));
        }
        let Some(seq) = fields.get("seq").and_then(Value::as_u64) else {
            return Err(Fail::Rejected("a receipt needs its number, seq".to_string()));
        };
        let mut unsigned = fields.clone();
        let sig = unsigned.remove("sig");
        let text = canonical(&Value::Object(unsigned)).map_err(|e| Fail::Rejected(format!("receipt: {e}")))?;
        if !signing::verify(&gate_key, &text, sig.as_ref().and_then(Value::as_str).unwrap_or("")) {
            return Err(Fail::Rejected("the receipt is not signed by the gate".to_string()));
        }
        if self.last_receipt_seq.is_some_and(|last| seq <= last) {
            return Err(Fail::Rejected(format!("receipt {seq} is not newer than the last one in the journal")));
        }
        let mut record = Map::new();
        record.insert("receipt".into(), Value::Object(fields.clone()));
        let n = self.append("gate_receipt", record).map_err(|e| self.enter_fault("append", e))?;
        self.last_receipt_seq = Some(seq);
        // A receipt that names a command record answers for it, whatever it decided. A
        // deadman receipt names the gate's head, which it does not answer for.
        if fields.get("decision").and_then(Value::as_str) != Some("deadman") {
            if let Some(of) = fields.get("n").and_then(Value::as_u64) {
                self.awaiting_receipt.remove(&(of as usize));
            }
        }
        Ok((n, seq))
    }

    /// How many command records this process has forwarded and has no receipt for yet.
    /// Always 0 when the configuration names no gate key.
    pub fn receipts_outstanding(&self) -> usize {
        self.awaiting_receipt.len()
    }

    /// Section 4.6: take the actuator's feedback for a command, signed with the feedback
    /// key, and write it into the journal as a record of its own. Returns the record's
    /// number and the feedback's.
    ///
    /// The same two checks as for a receipt: that the feedback is signed with the feedback
    /// key the configuration names, and that its number is higher than the last one
    /// written. Whether it names the right command, and what it says the actuator did, is
    /// the verifier's to judge, not the recorder's.
    pub fn actuator_feedback(&mut self, feedback: &Value) -> Result<(usize, u64), Fail> {
        if self.stopped {
            return Err(Fail::Rejected("the recorder has stopped".to_string()));
        }
        if let Some(why) = self.fault.clone() {
            return Err(Fail::Fault(why));
        }
        let Some(feedback_key) = self.config.feedback_public_key.clone() else {
            return Err(Fail::Rejected("the configuration names no feedback key".to_string()));
        };
        let fields = object(Some(feedback), "feedback")?;
        if fields.get("schema").and_then(Value::as_str) != Some(FEEDBACK_SCHEMA) {
            return Err(Fail::Rejected(format!("feedback's schema must be {FEEDBACK_SCHEMA}")));
        }
        let Some(seq) = fields.get("seq").and_then(Value::as_u64) else {
            return Err(Fail::Rejected("feedback needs its number, seq".to_string()));
        };
        let mut unsigned = fields.clone();
        let sig = unsigned.remove("sig");
        let text = canonical(&Value::Object(unsigned)).map_err(|e| Fail::Rejected(format!("feedback: {e}")))?;
        if !signing::verify(&feedback_key, &text, sig.as_ref().and_then(Value::as_str).unwrap_or("")) {
            return Err(Fail::Rejected("the feedback is not signed with the feedback key".to_string()));
        }
        if self.last_feedback_seq.is_some_and(|last| seq <= last) {
            return Err(Fail::Rejected(format!("feedback {seq} is not newer than the last one in the journal")));
        }
        let mut record = Map::new();
        record.insert("feedback".into(), Value::Object(fields.clone()));
        let n = self.append("actuator_feedback", record).map_err(|e| self.enter_fault("append", e))?;
        self.last_feedback_seq = Some(seq);
        if let Some(of) = fields.get("n").and_then(Value::as_u64) {
            self.awaiting_feedback.remove(&(of as usize));
        }
        Ok((n, seq))
    }

    /// How many command records this process has forwarded and has no feedback for yet.
    /// Always 0 when the configuration names no feedback key.
    pub fn feedback_outstanding(&self) -> usize {
        self.awaiting_feedback.len()
    }

    /// The limits for converting a ROS Twist, from the configuration in force.
    pub fn twist_limits(&self) -> Option<(i64, i64)> {
        self.config.twist_limits
    }

    /// A clean shutdown. Returns the root and the number of records.
    pub fn stop(&mut self) -> Result<(Option<String>, usize), String> {
        self.append("recorder_stop", Map::new())?;
        self.stopped = true;
        self.anchor(true)?;
        let state = load_state(&self.paths.state).map_err(|e| e.to_string())?;
        Ok((state.merkle_root, state.entry_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(dir: &Path, public: &str) {
        fs::create_dir_all(dir.join("software")).unwrap();
        fs::write(dir.join("software/fw.bin"), b"test firmware").unwrap();
        fs::write(
            dir.join("config.json"),
            format!(
                r#"{{"machine":"t","heartbeat_seconds":1,"measure_every":5,"safe_state_action":{{"speed_mm_s":0}},
                "recorder_public_key":"{public}","software":[{{"name":"fw","version":"1","file":"software/fw.bin"}}]}}"#
            ),
        )
        .unwrap();
        fs::write(dir.join("ruleset.json"), br#"{"ruleset_id":"t","kind":"declared","rules":[]}"#).unwrap();
    }

    /// Found by a ROS scenario: a heartbeat timer fired after the stop record was written
    /// and the root reported, and the journal grew by one record nobody had a root for.
    #[test]
    fn nothing_is_written_after_stop() {
        let dir = std::env::temp_dir().join(format!("sl-stop-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("recorder.key");
        let public = signing::generate(&key_file).unwrap();
        installed(&dir.join("installed"), &public);
        let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let mut r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, clock).unwrap();
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        let (root, entries) = r.stop().unwrap();

        // The fixed clock is now a second past the stop record, so a heartbeat is due.
        assert!(matches!(r.heartbeat_if_due(), Ok(false)));
        assert!(matches!(r.command(&json!({"requested": {"speed_mm_s": 2}})), Err(Fail::Rejected(_))));
        assert!(matches!(r.declare(&json!({})), Err(Fail::Rejected(_))));
        r.measure().unwrap();
        assert_eq!(r.tick(120).ok(), Some(0));

        let state = load_state(&dir.join("data/logchain.state")).unwrap();
        assert_eq!((state.merkle_root, state.entry_count), (root, entries));
        let _ = fs::remove_dir_all(&dir);
    }

    fn fresh(name: &str) -> (PathBuf, Recorder) {
        let dir = std::env::temp_dir().join(format!("sl-{name}-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("recorder.key");
        let public = signing::generate(&key_file).unwrap();
        installed(&dir.join("installed"), &public);
        let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, clock).unwrap();
        (dir, r)
    }

    fn records(dir: &Path) -> Vec<Value> {
        read_entries(&dir.join("data/logchain.journal"))
            .unwrap()
            .iter()
            .map(|e| serde_json::from_str(&e.raw).unwrap())
            .collect()
    }

    /// A recorder on the real clock, as the ROS node runs it. Heartbeat one second, so the
    /// verifier's threshold is two.
    fn live(name: &str) -> (PathBuf, Recorder) {
        let dir = std::env::temp_dir().join(format!("sl-{name}-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("recorder.key");
        let public = signing::generate(&key_file).unwrap();
        installed(&dir.join("installed"), &public);
        let link = Link::File(dir.join("link.jsonl"));
        let r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, Clock::System).unwrap();
        (dir, r)
    }

    /// Sleep until the wall clock is `millis` past a whole second.
    fn wait_for_fraction(millis: u32) {
        loop {
            let now = Utc::now().timestamp_subsec_millis();
            if now >= millis && now < millis + 40 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// What the verifier computes for two consecutive records: whole seconds between them.
    fn gap_seconds(earlier: &Value, later: &Value) -> i64 {
        let t = |r: &Value| parse_at(r["at"].as_str().unwrap()).unwrap().timestamp();
        t(later) - t(earlier)
    }

    fn kinds(all: &[Value]) -> Vec<&str> {
        all.iter().map(|x| x["kind"].as_str().unwrap()).collect()
    }

    /// Just over the threshold. A record written at 0.1 s past a second whose flush takes
    /// 3.2 s is followed by a record 3 whole seconds later: more than the verifier's 2.
    /// The record that follows must be a storage_stall that accounts for it, and the slow
    /// command must have gone to the gate before it.
    #[test]
    fn a_flush_that_leaves_a_gap_is_stated_in_the_next_record() {
        let (dir, mut r) = live("over");
        r.slow_flush_for_test("command", 2, std::time::Duration::from_millis(3200));
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        wait_for_fraction(100);
        let (slow_n, _) = r.command(&json!({"requested": {"speed_mm_s": 2}})).unwrap();
        r.command(&json!({"requested": {"speed_mm_s": 3}})).unwrap();
        r.stop().unwrap();

        let all = records(&dir);
        assert_eq!(kinds(&all)[slow_n..slow_n + 3], ["command", "storage_stall", "command"]);
        let stall = &all[slow_n + 1];
        assert_eq!(stall["of_record"], json!(slow_n));
        assert_eq!(stall["step"], json!("journal_write"));
        let ms = stall["stalled_ms"].as_i64().unwrap();
        assert!((3200..3900).contains(&ms), "stalled_ms was {ms}");
        // The verifier's two tests, applied to what was written: it is a gap, and the
        // stated time accounts for it.
        let gap = gap_seconds(&all[slow_n], stall);
        assert!(gap > 2, "gap was {gap}");
        assert!(gap * 1000 - ms <= 2000);
        // Every record went to the gate, in order: the slow command before the record about it.
        let link = fs::read_to_string(dir.join("link.jsonl")).unwrap();
        let sent: Vec<u64> = link.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["n"].as_u64().unwrap()).collect();
        assert_eq!(sent, (0..all.len() as u64).collect::<Vec<_>>());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Just under. The same, with a flush of 2.5 s: longer than two seconds on a
    /// stopwatch, but the next record is 2 whole seconds later, which the verifier does
    /// not call a gap. No stall record is written, because there is no gap to explain.
    /// The recorder and the verifier agree because they apply the same test.
    #[test]
    fn a_flush_that_leaves_no_gap_by_the_verifiers_measure_is_not_called_a_stall() {
        let (dir, mut r) = live("under");
        r.slow_flush_for_test("command", 2, std::time::Duration::from_millis(2500));
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        wait_for_fraction(100);
        let (slow_n, _) = r.command(&json!({"requested": {"speed_mm_s": 2}})).unwrap();
        r.command(&json!({"requested": {"speed_mm_s": 3}})).unwrap();
        r.stop().unwrap();

        let all = records(&dir);
        assert!(!kinds(&all).contains(&"storage_stall"), "{:?}", kinds(&all));
        assert_eq!(gap_seconds(&all[slow_n], &all[slow_n + 1]), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The case rounding used to lose. A flush of 1.9 s is under two seconds on a
    /// stopwatch. Started at 0.9 s past a second and followed by a short idle wait, it
    /// puts the next record 3 whole seconds later, which the verifier calls a gap. The
    /// recorder applies the verifier's test, sees the gap, and states the 1.9 s. The gap
    /// less the stated time is within the allowance, so the verifier reports a storage
    /// stall and not an unexplained gap.
    #[test]
    fn a_gap_that_exists_only_in_whole_seconds_is_still_explained() {
        let (dir, mut r) = live("rounding");
        r.slow_flush_for_test("command", 2, std::time::Duration::from_millis(1900));
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        wait_for_fraction(900);
        let (slow_n, _) = r.command(&json!({"requested": {"speed_mm_s": 2}})).unwrap();
        // Idle until just past the next whole second, as a heartbeat poll might be.
        wait_for_fraction(60);
        r.command(&json!({"requested": {"speed_mm_s": 3}})).unwrap();
        r.stop().unwrap();

        let all = records(&dir);
        assert_eq!(kinds(&all)[slow_n..slow_n + 3], ["command", "storage_stall", "command"]);
        let stall = &all[slow_n + 1];
        let ms = stall["stalled_ms"].as_i64().unwrap();
        assert!((1900..2000).contains(&ms), "stalled_ms was {ms}: under the two-second threshold on a stopwatch");
        let gap = gap_seconds(&all[slow_n], stall);
        assert_eq!(gap, 3);
        assert!(gap * 1000 - ms <= 2000);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A silence that storage does not account for is not dressed up as a stall. Here the
    /// recorder simply is not asked to do anything for four seconds (no heartbeat is
    /// written because nothing calls for one). The few milliseconds of storage time do
    /// not explain four seconds, and no stall record is written. The verifier will call
    /// it a gap, which it is.
    #[test]
    fn a_silence_that_storage_does_not_account_for_gets_no_stall_record() {
        let (dir, mut r) = live("silence");
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(4100));
        r.command(&json!({"requested": {"speed_mm_s": 2}})).unwrap();
        r.stop().unwrap();
        let all = records(&dir);
        assert!(!kinds(&all).contains(&"storage_stall"), "{:?}", kinds(&all));
        assert!(all.windows(2).any(|w| gap_seconds(&w[0], &w[1]) > 2));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A slow stop record is the one stall that is not stated: nothing follows a stop.
    #[test]
    fn a_stall_in_the_stop_record_writes_nothing_after_it() {
        let (dir, mut r) = live("stopstall");
        r.slow_flush_for_test("recorder_stop", 1, std::time::Duration::from_millis(3200));
        wait_for_fraction(100);
        r.stop().unwrap();
        assert!(matches!(r.heartbeat_if_due(), Ok(false)));
        assert!(matches!(r.record_pending(), Ok(())));
        assert_eq!(records(&dir).last().unwrap()["kind"], json!("recorder_stop"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// An anchor statement that cannot be written does not stop the recorder. The
    /// commands still go out, and the journal says, in a signed record, which statement
    /// was lost.
    #[test]
    fn an_anchor_that_cannot_be_written_is_stated_in_the_journal_and_is_not_a_fault() {
        let (dir, mut r) = fresh("anchorfail");
        let config = dir.join("installed/config.json");
        let text = fs::read_to_string(&config).unwrap().replace("\"measure_every\":5", "\"measure_every\":50,\"anchor_every\":2");
        // The setting is read when the recorder opens, so open it again with anchoring on.
        drop(r);
        fs::write(&config, text).unwrap();
        let _ = fs::remove_dir_all(dir.join("data"));
        let _ = fs::remove_file(dir.join("link.jsonl"));
        let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        r = Recorder::open(&dir.join("data"), &dir.join("installed"), &dir.join("recorder.key"), link, clock).unwrap();
        // Where the statements go is now a file, not a folder: every write there fails.
        fs::remove_dir_all(dir.join("data/anchors")).unwrap();
        fs::write(dir.join("data/anchors"), b"not a folder").unwrap();

        for speed in 1..=4 {
            assert!(r.command(&json!({"requested": {"speed_mm_s": speed}})).is_ok());
        }
        assert!(r.fault.is_none());
        let all = records(&dir);
        let failed: Vec<&Value> = all.iter().filter(|x| x["kind"] == json!("anchor_failed")).collect();
        assert!(!failed.is_empty(), "{:?}", kinds(&all));
        // The record names the statement that was lost, and comes after the records it covered.
        let first = failed[0];
        let covered = first["entry_count"].as_u64().unwrap();
        assert!(covered >= 2 && covered <= first["n"].as_u64().unwrap());
        assert!(first["detail"].as_str().unwrap().contains("cannot write"));
        assert!(first["sig"].as_str().unwrap().len() == 128);
        // All four commands went to the gate.
        let link = fs::read_to_string(dir.join("link.jsonl")).unwrap();
        assert_eq!(link.matches("\\\"kind\\\":\\\"command\\\"").count(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A recorder whose configuration names a gate key, and the gate's signing key.
    fn with_gate_key(name: &str) -> (PathBuf, Recorder, SigningKey) {
        let dir = std::env::temp_dir().join(format!("sl-{name}-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("recorder.key");
        let public = signing::generate(&key_file).unwrap();
        installed(&dir.join("installed"), &public);
        let gate = SigningKey::from_bytes(&[7u8; 32]);
        let config = dir.join("installed/config.json");
        let text = fs::read_to_string(&config)
            .unwrap()
            .replace("\"measure_every\":5", &format!("\"measure_every\":50,\"gate_public_key\":\"{}\"", signing::public_hex(&gate)));
        fs::write(&config, text).unwrap();
        let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, clock).unwrap();
        (dir, r, gate)
    }

    fn receipt(key: &SigningKey, seq: u64, decision: &str, reason: Value, n: Value) -> Value {
        let mut body = json!({"schema": GATE_RECEIPT_SCHEMA, "seq": seq, "decision": decision, "reason": reason,
            "detail": null, "n": n, "hash": null, "sent": {"speed_mm_s": 0}, "at_ms": null});
        let sig = signing::sign(key, &canonical(&body).unwrap());
        body["sig"] = json!(sig);
        body
    }

    /// A receipt signed by the gate becomes a signed record of the recorder's, holding the
    /// receipt whole, and answers for the command it names.
    #[test]
    fn a_receipt_signed_by_the_gate_is_written_as_a_record() {
        let (dir, mut r, gate) = with_gate_key("receipt");
        let (n, _) = r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        assert_eq!(r.receipts_outstanding(), 1);
        let sent = receipt(&gate, 0, "applied", Value::Null, json!(n));
        let (at, seq) = r.gate_receipt(&sent).unwrap();
        assert_eq!((seq, r.receipts_outstanding()), (0, 0));
        let all = records(&dir);
        assert_eq!(all[at]["kind"], json!("gate_receipt"));
        assert_eq!(all[at]["receipt"], sent);
        assert_eq!(all[at]["sig"].as_str().unwrap().len(), 128);
        // It went to the gate like every record, so the gate's head covers it.
        let link = fs::read_to_string(dir.join("link.jsonl")).unwrap();
        assert_eq!(link.lines().count(), all.len());
        // The settings in the first record name the gate's key.
        assert_eq!(all[0]["settings"]["gate_public_key"], json!(signing::public_hex(&gate)));
        let _ = fs::remove_dir_all(&dir);
    }

    /// What is not written: a receipt signed with another key, one whose contents were
    /// changed after signing, one sent twice, and anything that is not a receipt.
    #[test]
    fn a_receipt_the_gate_did_not_sign_or_already_sent_is_not_written() {
        let (dir, mut r, gate) = with_gate_key("badreceipt");
        let before = records(&dir).len();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let refused = |r: &mut Recorder, v: &Value| match r.gate_receipt(v) {
            Err(Fail::Rejected(why)) => why,
            _ => panic!("expected a rejection"),
        };
        assert!(refused(&mut r, &receipt(&other, 0, "applied", Value::Null, json!(2))).contains("not signed by the gate"));
        let mut changed = receipt(&gate, 0, "refused", json!("age"), json!(2));
        changed["decision"] = json!("applied");
        assert!(refused(&mut r, &changed).contains("not signed by the gate"));
        let mut unsigned = receipt(&gate, 0, "applied", Value::Null, json!(2));
        unsigned.as_object_mut().unwrap().remove("sig");
        assert!(refused(&mut r, &unsigned).contains("not signed by the gate"));
        assert!(refused(&mut r, &json!("receipt")).contains("JSON object"));
        assert!(refused(&mut r, &json!({"seq": 0})).contains("schema"));
        assert_eq!(records(&dir).len(), before);
        assert!(r.fault.is_none());

        r.gate_receipt(&receipt(&gate, 0, "refused", json!("signature"), Value::Null)).unwrap();
        r.gate_receipt(&receipt(&gate, 1, "refused", json!("chain"), Value::Null)).unwrap();
        // Sent again, by the gate or by anyone who saw it go past.
        assert!(refused(&mut r, &receipt(&gate, 1, "refused", json!("chain"), Value::Null)).contains("not newer"));
        assert!(refused(&mut r, &receipt(&gate, 0, "refused", json!("signature"), Value::Null)).contains("not newer"));
        assert_eq!(records(&dir).len(), before + 2);
        let _ = fs::remove_dir_all(&dir);
    }

    /// After a restart the recorder still knows the last receipt it wrote, from the journal.
    #[test]
    fn the_last_receipt_number_is_recovered_from_the_journal() {
        let (dir, mut r, gate) = with_gate_key("receiptrestart");
        r.gate_receipt(&receipt(&gate, 0, "refused", json!("form"), Value::Null)).unwrap();
        r.gate_receipt(&receipt(&gate, 1, "refused", json!("form"), Value::Null)).unwrap();
        r.stop().unwrap();
        drop(r);
        let clock = Clock::Fixed(parse_at("2026-10-01T09:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let mut r = Recorder::open(&dir.join("data"), &dir.join("installed"), &dir.join("recorder.key"), link, clock).unwrap();
        assert!(matches!(r.gate_receipt(&receipt(&gate, 1, "refused", json!("form"), Value::Null)), Err(Fail::Rejected(_))));
        assert!(r.gate_receipt(&receipt(&gate, 2, "refused", json!("form"), Value::Null)).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A machine whose configuration names no gate key takes no receipts and waits for none.
    #[test]
    fn without_a_gate_key_no_receipt_is_taken() {
        let (dir, mut r) = fresh("nogatekey");
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        assert_eq!(r.receipts_outstanding(), 0);
        let gate = SigningKey::from_bytes(&[7u8; 32]);
        match r.gate_receipt(&receipt(&gate, 0, "applied", Value::Null, json!(2))) {
            Err(Fail::Rejected(why)) => assert!(why.contains("no gate key")),
            _ => panic!("expected a rejection"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A recorder whose configuration names a feedback key, and that key.
    fn with_feedback_key(name: &str) -> (PathBuf, Recorder, SigningKey) {
        let dir = std::env::temp_dir().join(format!("sl-{name}-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("recorder.key");
        let public = signing::generate(&key_file).unwrap();
        installed(&dir.join("installed"), &public);
        let reporter = SigningKey::from_bytes(&[5u8; 32]);
        let config = dir.join("installed/config.json");
        let text = fs::read_to_string(&config).unwrap().replace(
            "\"measure_every\":5",
            &format!("\"measure_every\":50,\"feedback_public_key\":\"{}\"", signing::public_hex(&reporter)),
        );
        fs::write(&config, text).unwrap();
        let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, clock).unwrap();
        (dir, r, reporter)
    }

    fn feedback(key: &SigningKey, seq: u64, n: Value, speed: i64) -> Value {
        let mut body = json!({"schema": FEEDBACK_SCHEMA, "seq": seq, "n": n, "hash": null,
            "sent": {"speed_mm_s": speed}, "measured": {"speed_mm_s": speed}, "state": null,
            "after_ms": 50, "at_ms": null});
        let sig = signing::sign(key, &canonical(&body).unwrap());
        body["sig"] = json!(sig);
        body
    }

    /// Feedback signed with the feedback key becomes a signed record of the recorder's,
    /// holding the feedback whole, and answers for the command it names.
    #[test]
    fn feedback_signed_with_the_feedback_key_is_written_as_a_record() {
        let (dir, mut r, reporter) = with_feedback_key("feedback");
        let (n, _) = r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        assert_eq!((r.feedback_outstanding(), r.receipts_outstanding()), (1, 0));
        let sent = feedback(&reporter, 0, json!(n), 1);
        let (at, seq) = r.actuator_feedback(&sent).unwrap();
        assert_eq!((seq, r.feedback_outstanding()), (0, 0));
        let all = records(&dir);
        assert_eq!(all[at]["kind"], json!("actuator_feedback"));
        assert_eq!(all[at]["feedback"], sent);
        assert_eq!(all[at]["sig"].as_str().unwrap().len(), 128);
        // It went to the gate like every record, so the gate's head covers it.
        let link = fs::read_to_string(dir.join("link.jsonl")).unwrap();
        assert_eq!(link.lines().count(), all.len());
        assert_eq!(all[0]["settings"]["feedback_public_key"], json!(signing::public_hex(&reporter)));
        let _ = fs::remove_dir_all(&dir);
    }

    /// What is not written: feedback signed with another key, feedback whose contents or
    /// command were changed after signing, feedback sent twice, and anything that is not
    /// feedback.
    #[test]
    fn feedback_not_signed_with_the_feedback_key_or_already_sent_is_not_written() {
        let (dir, mut r, reporter) = with_feedback_key("badfeedback");
        let before = records(&dir).len();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let refused = |r: &mut Recorder, v: &Value| match r.actuator_feedback(v) {
            Err(Fail::Rejected(why)) => why,
            _ => panic!("expected a rejection"),
        };
        assert!(refused(&mut r, &feedback(&other, 0, json!(2), 1)).contains("not signed with the feedback key"));
        let mut changed = feedback(&reporter, 0, json!(2), 1);
        changed["measured"] = json!({"speed_mm_s": 900});
        assert!(refused(&mut r, &changed).contains("not signed with the feedback key"));
        let mut moved = feedback(&reporter, 0, json!(2), 1);
        moved["n"] = json!(3);
        assert!(refused(&mut r, &moved).contains("not signed with the feedback key"));
        let mut unsigned = feedback(&reporter, 0, json!(2), 1);
        unsigned.as_object_mut().unwrap().remove("sig");
        assert!(refused(&mut r, &unsigned).contains("not signed with the feedback key"));
        assert!(refused(&mut r, &json!("feedback")).contains("JSON object"));
        assert!(refused(&mut r, &json!({"seq": 0})).contains("schema"));
        assert_eq!(records(&dir).len(), before);
        assert!(r.fault.is_none());

        r.actuator_feedback(&feedback(&reporter, 0, json!(2), 1)).unwrap();
        r.actuator_feedback(&feedback(&reporter, 1, json!(3), 1)).unwrap();
        // Sent again, by the reporter or by anyone who saw it go past.
        assert!(refused(&mut r, &feedback(&reporter, 1, json!(3), 1)).contains("not newer"));
        assert!(refused(&mut r, &feedback(&reporter, 0, json!(2), 1)).contains("not newer"));
        assert_eq!(records(&dir).len(), before + 2);
        let _ = fs::remove_dir_all(&dir);
    }

    /// After a restart the recorder still knows the last feedback it wrote, from the journal.
    #[test]
    fn the_last_feedback_number_is_recovered_from_the_journal() {
        let (dir, mut r, reporter) = with_feedback_key("feedbackrestart");
        r.actuator_feedback(&feedback(&reporter, 0, json!(2), 1)).unwrap();
        r.actuator_feedback(&feedback(&reporter, 1, json!(3), 1)).unwrap();
        r.stop().unwrap();
        drop(r);
        let clock = Clock::Fixed(parse_at("2026-10-01T09:00:00Z").unwrap());
        let link = Link::File(dir.join("link.jsonl"));
        let mut r = Recorder::open(&dir.join("data"), &dir.join("installed"), &dir.join("recorder.key"), link, clock).unwrap();
        assert!(matches!(r.actuator_feedback(&feedback(&reporter, 1, json!(3), 1)), Err(Fail::Rejected(_))));
        assert!(r.actuator_feedback(&feedback(&reporter, 2, json!(4), 1)).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A machine whose configuration names no feedback key takes none and waits for none.
    #[test]
    fn without_a_feedback_key_no_feedback_is_taken() {
        let (dir, mut r) = fresh("nofeedbackkey");
        r.command(&json!({"requested": {"speed_mm_s": 1}})).unwrap();
        assert_eq!(r.feedback_outstanding(), 0);
        let reporter = SigningKey::from_bytes(&[5u8; 32]);
        match r.actuator_feedback(&feedback(&reporter, 0, json!(2), 1)) {
            Err(Fail::Rejected(why)) => assert!(why.contains("no feedback key")),
            _ => panic!("expected a rejection"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The feedback key cannot be changed: not by a declared change, and not behind the
    /// recorder's back.
    #[test]
    fn the_feedback_key_cannot_be_changed() {
        let (dir, mut r, reporter) = with_feedback_key("feedbackrotation");
        let config = dir.join("installed/config.json");
        let text = fs::read_to_string(&config).unwrap();
        let (now, other) = (signing::public_hex(&reporter), signing::public_hex(&SigningKey::from_bytes(&[6u8; 32])));
        assert!(text.contains(&now));
        let changed = dir.join("changed.json");
        fs::write(&changed, text.replace(&now, &other)).unwrap();
        let declared = r.declare(&json!({"target": "config", "file": changed.to_str().unwrap(),
            "operator": "o", "reference": "r"}));
        assert!(matches!(declared, Err(Fail::Rejected(why)) if why.contains("key rotation")));
        fs::write(&config, text.replace(&now, &other)).unwrap();
        assert!(r.measure().unwrap_err().contains("different feedback key"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// With `anchor_out` set the recorder writes no anchor itself. What it hands over is
    /// byte for byte the statement it would have written.
    #[test]
    fn anchors_handed_over_are_the_statements_it_would_have_written() {
        let config = |dir: &Path| {
            let p = dir.join("installed/config.json");
            let text = fs::read_to_string(&p).unwrap().replace("\"measure_every\":5", "\"measure_every\":5,\"anchor_every\":2");
            fs::write(&p, text).unwrap();
        };
        let run = |name: &str, hand_over: bool| {
            let dir = std::env::temp_dir().join(format!("sl-{name}-test-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let key_file = dir.join("recorder.key");
            // The same key both times, so the two journals are the same journal.
            fs::write(&key_file, format!("{}\n", "11".repeat(32))).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let public = signing::public_hex(&signing::load_key(&key_file).unwrap());
            installed(&dir.join("installed"), &public);
            config(&dir);
            let clock = Clock::Fixed(parse_at("2026-10-01T08:00:00Z").unwrap());
            let link = Link::File(dir.join("link.jsonl"));
            let mut r = Recorder::open(&dir.join("data"), &dir.join("installed"), &key_file, link, clock).unwrap();
            let taken = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            if hand_over {
                let taken = std::sync::Arc::clone(&taken);
                r.anchor_out = Some(Box::new(move |path, bytes| taken.lock().unwrap().push((path, bytes))));
            }
            for speed in 1..=3 {
                r.command(&json!({"requested": {"speed_mm_s": speed}})).unwrap();
            }
            r.stop().unwrap();
            let handed = taken.lock().unwrap().clone();
            (dir, handed)
        };
        let (wrote_dir, none) = run("anchorsync", false);
        let (handed_dir, handed) = run("anchorhand", true);
        assert!(none.is_empty());
        let listing = |dir: &Path| {
            let mut found: Vec<_> = fs::read_dir(dir.join("data/anchors")).unwrap().map(|e| e.unwrap().path()).collect();
            found.sort();
            found
        };
        // Opening the journal writes its first two records before anyone can set
        // `anchor_out`, so the anchor for those two is on disk in both runs.
        let early = listing(&handed_dir);
        assert_eq!(early.len(), 1);
        let written = listing(&wrote_dir);
        // The stop writes the last statement a second time under the same name.
        let mut handed = handed;
        handed.dedup_by(|later, earlier| later.0 == earlier.0);
        assert!(handed.len() >= 2 && written.len() == early.len() + handed.len());
        assert_eq!(fs::read(&written[0]).unwrap(), fs::read(&early[0]).unwrap());
        for (path, (handed_path, bytes)) in written[1..].iter().zip(&handed) {
            assert_eq!(path.file_name(), handed_path.file_name());
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
        let _ = fs::remove_dir_all(&wrote_dir);
        let _ = fs::remove_dir_all(&handed_dir);
    }
}
