//! Command line for the recorder.
//!
//!     sentinel-recorder keygen --out FILE
//!     sentinel-recorder run --dir DATA --installed DIR --key FILE --link FILE [--start-at T]
//!     sentinel-recorder root --dir DATA
//!     sentinel-recorder receipt --dir DATA --n N
//!
//! `run` reads one JSON operation per line from standard input and answers each with
//! one JSON line on standard output. Exit codes: 0 stopped cleanly, 3 ended in the safe
//! state, 1 usage or I/O error.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use logchain::journal::{DataPaths, leaf_hashes, load_state, read_entries};
use logchain::report::build_inclusion_proof;
use sentinel_recorder::recorder::{Clock, Fail, Link, Recorder, parse_at};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "sentinel-recorder", about = "Records every actuator command before forwarding it")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record and forward the operations read from standard input.
    Run {
        /// Data directory: the journal, archived rulesets and decision files.
        #[arg(long)]
        dir: PathBuf,
        /// Installed files: config.json, ruleset.json and the software they name.
        #[arg(long)]
        installed: PathBuf,
        /// The recorder's private signing key (made with `keygen`). Keep it outside the
        /// data directory and readable by the recorder's user only.
        #[arg(long)]
        key: PathBuf,
        /// The wire to the actuator-side gate: a file each forwarded record is appended to.
        #[arg(long)]
        link: PathBuf,
        /// Use a fixed clock starting here (2026-10-01T08:00:00Z) and moving one second
        /// per record. For reproducible demos. Without it the system clock is used.
        #[arg(long)]
        start_at: Option<String>,
    },
    /// Make a signing key. Writes the private key to a new file and prints the public key,
    /// which goes in the configuration file as recorder_public_key.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the current Merkle root from the state file.
    Root {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Print a receipt for record N: the record and a LogChain inclusion proof.
    Receipt {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        n: usize,
    },
}

fn say(v: Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

/// The recorder could not start. Tell the gate to go to the safe state, so a failed
/// start and a failed write end in the same place.
fn safe_state_without_recorder(link: &Path) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(link) {
        let _ = writeln!(f, "{}", json!({"type": "safe_state", "why": "recorder_fault"}));
    }
}

fn run(dir: &Path, installed: &Path, key: &Path, link: &Path, start_at: Option<String>) -> ExitCode {
    let clock = match start_at {
        None => Clock::System,
        Some(text) => match parse_at(&text) {
            Ok(t) => Clock::Fixed(t),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(1);
            }
        },
    };
    let mut recorder = match Recorder::open(dir, installed, key, Link::File(link.to_path_buf()), clock) {
        Ok(r) => r,
        Err(e) => {
            safe_state_without_recorder(link);
            say(json!({"ok": false, "fault": true, "error": format!("could not start: {e}")}));
            return ExitCode::from(3);
        }
    };

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let op: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                say(json!({"ok": false, "fault": false, "error": format!("not JSON: {e}")}));
                continue;
            }
        };
        let result = match op.get("op").and_then(Value::as_str) {
            Some("command") => {
                recorder.command(&op).map(|(n, outcome)| json!({"ok": true, "n": n, "outcome": outcome}))
            }
            Some("declare") => recorder.declare(&op).map(|n| json!({"ok": true, "n": n})),
            // A receipt signed by the gate, to be written into the journal (section 4.5).
            Some("gate_receipt") => recorder
                .gate_receipt(op.get("receipt").unwrap_or(&Value::Null))
                .map(|(n, seq)| json!({"ok": true, "n": n, "seq": seq})),
            Some("tick") => recorder
                .tick(op.get("seconds").and_then(Value::as_i64).unwrap_or(0))
                .map(|written| json!({"ok": true, "heartbeats": written})),
            Some("measure") => match recorder.measure() {
                Ok(()) => Ok(json!({"ok": true})),
                Err(e) => Err(Fail::Fault(e)),
            },
            other => Err(Fail::Rejected(format!("unknown op {other:?}"))),
        };
        match result {
            Ok(v) => say(v),
            Err(Fail::Rejected(e)) => say(json!({"ok": false, "fault": false, "error": e})),
            Err(Fail::Fault(e)) => say(json!({"ok": false, "fault": true, "error": e})),
        }
    }

    if recorder.fault.is_some() {
        return ExitCode::from(3);
    }
    match recorder.stop() {
        Ok((root, entries)) => {
            say(json!({"ok": true, "stopped": true, "root": root, "entries": entries}));
            ExitCode::SUCCESS
        }
        Err(e) => {
            say(json!({"ok": false, "fault": true, "error": e}));
            ExitCode::from(3)
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run { dir, installed, key, link, start_at } => run(&dir, &installed, &key, &link, start_at),
        Command::Keygen { out } => match sentinel_recorder::signing::generate(&out) {
            Ok(public) => {
                say(json!({"recorder_public_key": public}));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Command::Root { dir } => match load_state(&DataPaths::from_dir(&dir).state) {
            Ok(state) => {
                say(json!({"root": state.merkle_root, "entries": state.entry_count}));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Command::Receipt { dir, n } => {
            let paths = DataPaths::from_dir(&dir);
            let built = read_entries(&paths.journal).and_then(|entries| {
                let leaves = leaf_hashes(&entries)?;
                Ok(build_inclusion_proof(n, &entries, &leaves).map(|proof| (entries[n].raw.clone(), proof)))
            });
            match built {
                Ok(Some((record, proof))) => {
                    let receipt = json!({
                        "receipt_schema": "sentinel-ledger/receipt/0",
                        "record": record,
                        "proof": proof,
                    });
                    println!("{}", serde_json::to_string_pretty(&receipt).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("error: no record {n}");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
