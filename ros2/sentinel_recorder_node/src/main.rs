//! The recorder as a ROS 2 node. docs/SPEC.md section 15.
//!
//! Topics:
//!   cmd_vel_in        geometry_msgs/Twist  in   the command a controller requests
//!   safety_inputs     std_msgs/String      in   JSON object of integers, e.g. {"light_curtain_clear":1}
//!   recorder_control  std_msgs/String      in   JSON: {"op":"declare",...} | {"op":"measure"} | {"op":"stop"}
//!   gate_receipts     std_msgs/String      in   a receipt signed by the gate, written to the journal as a record
//!   cmd_vel_out       std_msgs/String      out  one message per record: its text, number and hash
//!   recorder_status   std_msgs/String      out  one JSON reply for each input handled
//!
//! Nothing but recorded commands goes out on cmd_vel_out. The node holds no publisher of
//! plain Twist. The gate that turns a record back into motion is on the robot's side.
//!
//! Environment: SL_DATA_DIR (journal), SL_INSTALLED (config.json, ruleset.json, software),
//! SL_KEY_FILE (the private signing key, outside the journal's directory),
//! SL_EXIT_FILE (optional: the exit code is also written here, for a launcher),
//! SL_TRACE_FILE (optional, for diagnosis: timings are appended here, one line each, as
//! monotonic seconds, wall-clock seconds, process id, event, details).
//! Exit codes: 0 stopped in an orderly way, 3 ended in the safe state, 1 could not start.

use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rclrs::*;
use ros_env::*;
use sentinel_recorder::recorder::{write_anchor, Clock, Fail, Link, Recorder};
use sentinel_recorder::twist;
use serde_json::{json, Map, Value};

type Text = std_msgs::msg::String;

struct Shared {
    recorder: Recorder,
    /// The latest safety inputs received. Empty until the first arrive, and the rules
    /// treat a missing input as unsafe.
    inputs: Map<String, Value>,
    handled: u64,
    /// A stop was asked for while commands were still waiting for the gate's receipt.
    /// The stop record is written when the last receipt is in, or at this time.
    stop_by: Option<Instant>,
}

/// How long a stop waits for the receipts of commands already forwarded.
const STOP_WAITS_FOR_RECEIPTS: Duration = Duration::from_secs(2);

/// Write the stop record and say how it went. Returns the reply and the exit code.
fn stop_now(s: &mut Shared, failed: &Mutex<Vec<(usize, String)>>) -> (Value, i32) {
    s.stop_by = None;
    // Anchor failures not yet in the journal go in before the stop record.
    for (covered, why) in failed.lock().unwrap().drain(..) {
        s.recorder.anchor_failed(covered, why);
    }
    let without_receipt = s.recorder.receipts_outstanding();
    if s.recorder.fault.is_some() {
        return (json!({"ok": false, "fault": true, "stopped": true}), 3);
    }
    match s.recorder.stop() {
        Ok((root, entries)) => {
            (json!({"ok": true, "stopped": true, "root": root, "entries": entries, "commands_without_receipt": without_receipt}), 0)
        }
        Err(e) => (json!({"ok": false, "fault": true, "stopped": true, "error": e}), 3),
    }
}

/// Finish a stop that was waiting for receipts, if it need wait no longer.
fn finish_stop(s: &mut Shared, failed: &Mutex<Vec<(usize, String)>>, stop: &AtomicI32, tell: &dyn Fn(Value)) {
    let Some(by) = s.stop_by else { return };
    if s.recorder.receipts_outstanding() > 0 && Instant::now() < by && s.recorder.fault.is_none() {
        return;
    }
    let (mut v, code) = stop_now(s, failed);
    v["kind"] = json!("stop");
    v["handled"] = json!(s.handled);
    stop.store(code, Ordering::SeqCst);
    tell(v);
}

/// Timings for diagnosis, written only when SL_TRACE_FILE is set. Each line carries the
/// monotonic clock (CLOCK_MONOTONIC, the one a wall-clock step does not move) next to the
/// wall clock, so a stall here can be laid beside a clock log kept by another process.
#[derive(Clone)]
struct Trace(Option<Arc<Mutex<std::fs::File>>>);

fn clock(id: libc::clockid_t) -> f64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // Safe: `t` is a valid timespec and the clock ids used here always exist on Linux.
    unsafe { libc::clock_gettime(id, &mut t) };
    t.tv_sec as f64 + t.tv_nsec as f64 * 1e-9
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e6).round() / 1e3
}

impl Trace {
    fn from_env() -> Trace {
        let file = std::env::var("SL_TRACE_FILE")
            .ok()
            .and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok());
        Trace(file.map(|f| Arc::new(Mutex::new(f))))
    }

    fn line(&self, event: &str, detail: Value) {
        use std::io::Write;
        if let Some(file) = &self.0 {
            let text = format!(
                "{:.6} {:.6} {} {} {}\n",
                clock(libc::CLOCK_MONOTONIC),
                clock(libc::CLOCK_REALTIME),
                std::process::id(),
                event,
                detail
            );
            let _ = file.lock().unwrap().write_all(text.as_bytes());
        }
    }
}

/// The exit code once a stop has been asked for. Kept outside the lock so the main loop
/// can look at it without competing with the recorder for the lock.
const RUNNING: i32 = -1;

fn reply(result: Result<Value, Fail>) -> Value {
    match result {
        Ok(mut v) => {
            v["ok"] = json!(true);
            v
        }
        Err(Fail::Rejected(e)) => json!({"ok": false, "fault": false, "error": e}),
        Err(Fail::Fault(e)) => json!({"ok": false, "fault": true, "error": e}),
    }
}

fn run() -> Result<i32, String> {
    let dir = PathBuf::from(std::env::var("SL_DATA_DIR").map_err(|_| "SL_DATA_DIR is not set")?);
    let installed = PathBuf::from(std::env::var("SL_INSTALLED").map_err(|_| "SL_INSTALLED is not set")?);
    let key_file = PathBuf::from(std::env::var("SL_KEY_FILE").map_err(|_| "SL_KEY_FILE is not set")?);
    let trace = Trace::from_env();
    trace.line("start", json!({"data_dir": dir.display().to_string()}));

    let context = Context::default_from_env().map_err(|e| e.to_string())?;
    let mut executor = context.create_basic_executor();
    let node = executor.create_node("sentinel_recorder").map_err(|e| e.to_string())?;

    // Late joiners must get the records from the start, or the gate could never accept
    // the chain: transient local, reliable, with a deep history.
    let out = node
        .create_publisher::<Text>("cmd_vel_out".keep_last(1000).reliable().transient_local())
        .map_err(|e| e.to_string())?;
    let status = node
        .create_publisher::<Text>("recorder_status".keep_last(1000).reliable().transient_local())
        .map_err(|e| e.to_string())?;
    // Publishing is done by one thread that owns both publishers and takes messages
    // from a queue, in order. The recorder never waits on the middleware: while it holds
    // its lock it only puts a line on the queue. This matters for more than speed. With
    // publishing done under the lock, a publish that was slow (seen while late-joining
    // subscribers were being matched) held up the heartbeat for seconds.
    enum Out {
        Record(String),
        Status(String),
    }
    let (queue, outbox) = mpsc::channel::<Out>();
    let pending = Arc::new(AtomicUsize::new(0));
    {
        let (out, status, pending) = (Arc::clone(&out), Arc::clone(&status), Arc::clone(&pending));
        let trace = trace.clone();
        std::thread::spawn(move || {
            for message in outbox {
                let began = Instant::now();
                let _ = match message {
                    Out::Record(data) => out.publish(Text { data }),
                    Out::Status(data) => status.publish(Text { data }),
                };
                if began.elapsed() > Duration::from_millis(50) {
                    trace.line("publish_slow", json!({"ms": ms(began.elapsed())}));
                }
                pending.fetch_sub(1, Ordering::SeqCst);
            }
        });
    }
    let say = {
        let (queue, pending) = (queue.clone(), Arc::clone(&pending));
        move |v: Value| {
            pending.fetch_add(1, Ordering::SeqCst);
            let _ = queue.send(Out::Status(v.to_string()));
        }
    };

    let (link_queue, link_pending) = (queue.clone(), Arc::clone(&pending));
    let sent = AtomicUsize::new(0);
    let link = Link::Sink(Box::new(move |line: &str| {
        let count = sent.fetch_add(1, Ordering::SeqCst);
        if cfg!(feature = "planted-bug-ros-drops-a-record") && count == 3 {
            return Ok(());
        }
        link_pending.fetch_add(1, Ordering::SeqCst);
        link_queue.send(Out::Record(line.to_string())).map_err(|e| format!("cmd_vel_out: {e}"))
    }));

    // Anchor statements are written and flushed by a thread of their own. The recorder,
    // holding its lock, only puts the statement on a queue. Measured on a WSL 2 disk, one
    // anchor flush took 7.8 s, and while it was done under the lock no record could be
    // written for that long. An anchor is evidence about records already on disk, so no
    // record waits for it. One that cannot be written does not stop the machine. The
    // failure is handed back to the recorder, which states it in the journal in a signed
    // record (`anchor_failed`); a line on recorder_status alone would be gone with the
    // process.
    let (anchor_queue, anchors) = mpsc::channel::<(PathBuf, Vec<u8>)>();
    let anchor_failures: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let (pending, trace, tell) = (Arc::clone(&pending), trace.clone(), say.clone());
        let failures = Arc::clone(&anchor_failures);
        std::thread::spawn(move || {
            for (path, bytes) in anchors {
                let began = Instant::now();
                let written = write_anchor(&path, &bytes);
                trace.line("step", json!({"step": "anchor_write_fsync", "ms": ms(began.elapsed()), "off_lock": true}));
                if let Err(e) = written {
                    // The statement's file name is the entry count it covers.
                    let covered = path.file_stem().and_then(|n| n.to_str()).and_then(|n| n.parse().ok()).unwrap_or(0);
                    failures.lock().unwrap().push((covered, e.clone()));
                    tell(json!({"kind": "anchor", "ok": false, "fault": false, "error": e}));
                }
                pending.fetch_sub(1, Ordering::SeqCst);
            }
        });
    }

    let recorder = match Recorder::open(&dir, &installed, &key_file, link, Clock::System) {
        Ok(mut r) => {
            let anchor_pending = Arc::clone(&pending);
            r.anchor_out = Some(Box::new(move |path, bytes| {
                anchor_pending.fetch_add(1, Ordering::SeqCst);
                if anchor_queue.send((path, bytes)).is_err() {
                    anchor_pending.fetch_sub(1, Ordering::SeqCst);
                }
            }));
            if trace.0.is_some() {
                let trace = trace.clone();
                r.timing = Some(Box::new(move |step, took| trace.line("step", json!({"step": step, "ms": ms(took)}))));
            }
            r
        }
        Err(e) => {
            pending.fetch_add(1, Ordering::SeqCst);
            let _ = queue.send(Out::Record(json!({"type": "safe_state", "why": "recorder_fault"}).to_string()));
            say(json!({"kind": "start", "ok": false, "fault": true, "error": e}));
            while pending.load(Ordering::SeqCst) > 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = executor.spin(SpinOptions::default().timeout(Duration::from_millis(500)));
            return Ok(3);
        }
    };
    if recorder.twist_limits().is_none() {
        return Err("the configuration has no twist_limits".to_string());
    }
    let shared = Arc::new(Mutex::new(Shared { recorder, inputs: Map::new(), handled: 0, stop_by: None }));

    let (s, tell, tracing) = (Arc::clone(&shared), say.clone(), trace.clone());
    let _commands = node
        .create_subscription::<geometry_msgs::msg::Twist, _>(
            "cmd_vel_in".keep_last(100).reliable(),
            move |msg: geometry_msgs::msg::Twist| {
                let arrived = Instant::now();
                // When this command arrived, on the wall clock, taken before waiting for
                // anything. The gate measures the command's age from it.
                let received_ms = (clock(libc::CLOCK_REALTIME) * 1000.0) as i64;
                let mut s = s.lock().unwrap();
                let locked = Instant::now();
                s.handled += 1;
                let values = [msg.linear.x, msg.linear.y, msg.linear.z, msg.angular.x, msg.angular.y, msg.angular.z];
                let limits = s.recorder.twist_limits().unwrap_or((0, 0));
                let result = match twist::to_command(values, limits) {
                    Err(e) => Err(Fail::Rejected(e)),
                    Ok(requested) => {
                        let op = json!({"requested": requested, "safety_inputs": s.inputs.clone(), "received_ms": received_ms});
                        s.recorder.command(&op).map(|(n, outcome)| json!({"n": n, "outcome": outcome}))
                    }
                };
                let mut v = reply(result);
                v["kind"] = json!("command");
                v["handled"] = json!(s.handled);
                tracing.line(
                    "command",
                    json!({"n": v["n"], "lock_wait_ms": ms(locked - arrived), "hold_ms": ms(locked.elapsed())}),
                );
                tell(v);
            },
        )
        .map_err(|e| e.to_string())?;

    let (s, tell) = (Arc::clone(&shared), say.clone());
    let _inputs = node
        .create_subscription::<Text, _>("safety_inputs".keep_last(100).reliable(), move |msg: Text| {
            let mut s = s.lock().unwrap();
            s.handled += 1;
            let parsed: Option<Map<String, Value>> = serde_json::from_str(&msg.data).ok();
            let good = parsed.filter(|m| m.values().all(|v| v.is_i64()));
            let ok = good.is_some();
            if let Some(m) = good {
                s.inputs = m;
            } else {
                // An unreadable safety message leaves no inputs at all: unsafe.
                s.inputs = Map::new();
            }
            tell(json!({"kind": "safety_inputs", "ok": ok, "handled": s.handled}));
        })
        .map_err(|e| e.to_string())?;

    let stop = Arc::new(AtomicI32::new(RUNNING));

    // The gate's receipts (section 4.5). Each one that is signed by the gate and newer
    // than the last becomes a record. The topic is the robot's to publish on, and any
    // node can: what is not the gate's is not written.
    let (s, tell, stopping) = (Arc::clone(&shared), say.clone(), Arc::clone(&stop));
    let failed = Arc::clone(&anchor_failures);
    let _receipts = node
        .create_subscription::<Text, _>("gate_receipts".keep_last(1000).reliable().transient_local(), move |msg: Text| {
            let mut s = s.lock().unwrap();
            s.handled += 1;
            let receipt: Value = serde_json::from_str(&msg.data).unwrap_or(Value::Null);
            let of = receipt.get("n").cloned().unwrap_or(Value::Null);
            let mut v = reply(s.recorder.gate_receipt(&receipt).map(|(n, seq)| json!({"n": n, "seq": seq, "of": of})));
            v["kind"] = json!("gate_receipt");
            v["handled"] = json!(s.handled);
            tell(v);
            finish_stop(&mut s, &failed, &stopping, &tell);
        })
        .map_err(|e| e.to_string())?;

    let (s, tell, stopping, tracing) = (Arc::clone(&shared), say.clone(), Arc::clone(&stop), trace.clone());
    let failed = Arc::clone(&anchor_failures);
    let _control = node
        .create_subscription::<Text, _>("recorder_control".keep_last(100).reliable(), move |msg: Text| {
            let arrived = Instant::now();
            let mut s = s.lock().unwrap();
            let locked = Instant::now();
            s.handled += 1;
            let op: Value = serde_json::from_str(&msg.data).unwrap_or(Value::Null);
            let name = op.get("op").and_then(Value::as_str).unwrap_or("").to_string();
            let mut v = match name.as_str() {
                "declare" => reply(s.recorder.declare(&op).map(|n| json!({"n": n}))),
                "measure" => reply(s.recorder.measure().map(|_| json!({})).map_err(Fail::Fault)),
                "stop" => {
                    if s.recorder.receipts_outstanding() > 0 && s.recorder.fault.is_none() {
                        // Commands have gone to the gate whose receipts are not back yet.
                        // Nothing is written after the stop record, so the stop waits for
                        // them, for a bounded time. The reply is sent when it is done.
                        s.stop_by = Some(Instant::now() + STOP_WAITS_FOR_RECEIPTS);
                        tracing.line("control", json!({"op": name, "waiting_for_receipts": s.recorder.receipts_outstanding()}));
                        return;
                    }
                    let (v, code) = stop_now(&mut s, &failed);
                    stopping.store(code, Ordering::SeqCst);
                    v
                }
                _ => json!({"ok": false, "fault": false, "error": "unknown op"}),
            };
            v["kind"] = json!(name);
            v["handled"] = json!(s.handled);
            tracing.line(
                "control",
                json!({"op": name, "lock_wait_ms": ms(locked - arrived), "hold_ms": ms(locked.elapsed())}),
            );
            tell(v);
        })
        .map_err(|e| e.to_string())?;

    // The heartbeat runs on a thread of its own and does not depend on the executor.
    // Two earlier versions did (a check between calls to spin with a timeout, then a ROS
    // timer) and both missed heartbeats, because the executor did not always wake until
    // a message arrived.
    let (s, tell, tracing, stopping) = (Arc::clone(&shared), say.clone(), trace.clone(), Arc::clone(&stop));
    let failed = Arc::clone(&anchor_failures);
    std::thread::spawn(move || loop {
        let slept_from = Instant::now();
        std::thread::sleep(Duration::from_millis(200));
        let woke = Instant::now();
        let lost: Vec<(usize, String)> = failed.lock().unwrap().drain(..).collect();
        let mut s = s.lock().unwrap();
        let locked = Instant::now();
        // An anchor the anchor thread could not write is stated in the journal now,
        // without waiting for the next command.
        for (covered, why) in lost {
            s.recorder.anchor_failed(covered, why);
        }
        let result = s.recorder.record_pending().and_then(|_| s.recorder.heartbeat_if_due());
        // A stop that has waited long enough for receipts goes ahead without them.
        finish_stop(&mut s, &failed, &stopping, &tell);
        let hold = locked.elapsed();
        drop(s);
        // One line for every heartbeat written, and one for any pass that overslept or
        // had to wait for the lock, whether or not a heartbeat was due.
        let wrote = matches!(result, Ok(true));
        if wrote || woke - slept_from > Duration::from_millis(400) || locked - woke > Duration::from_millis(50) {
            tracing.line(
                "heartbeat",
                json!({"wrote": wrote, "sleep_ms": ms(woke - slept_from), "lock_wait_ms": ms(locked - woke), "hold_ms": ms(hold)}),
            );
        }
        if let Err(Fail::Fault(e)) = result {
            tell(json!({"kind": "heartbeat", "ok": false, "fault": true, "error": e}));
        }
    });

    say(json!({"kind": "start", "ok": true}));
    loop {
        let began = Instant::now();
        let _ = executor.spin(SpinOptions::default().timeout(Duration::from_millis(100)));
        if began.elapsed() > Duration::from_millis(1000) {
            trace.line("spin_long", json!({"ms": ms(began.elapsed())}));
        }
        // This loop must not take the recorder's lock on every pass. An earlier version
        // did, to read a stop flag, and whenever spin returned at once the loop took the
        // lock again and again and kept the heartbeat thread waiting for seconds.
        let code = stop.load(Ordering::SeqCst);
        if code != RUNNING {
            // Let the queues empty (messages to publish, anchors to write), then give
            // the last messages time to leave.
            while pending.load(Ordering::SeqCst) > 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
            for _ in 0..5 {
                let _ = executor.spin(SpinOptions::default().timeout(Duration::from_millis(100)));
            }
            return Ok(code);
        }
        if !context.ok() {
            // Interrupted without a stop request: nothing more can be published, so no
            // stop record is written. The journal will show a recorder that ended
            // without an orderly shutdown, which is what happened.
            return Ok(if shared.lock().unwrap().recorder.fault.is_some() { 3 } else { 0 });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sentinel_recorder_node: {e}");
            1
        }
    };
    if let Ok(path) = std::env::var("SL_EXIT_FILE") {
        let _ = std::fs::write(path, json!({"exit": code}).to_string());
    }
    std::process::exit(code);
}
