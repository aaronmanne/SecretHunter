//! Operator progress on stderr. Messages are internal status text only: file names,
//! refs, and other target-controlled strings are never rendered because they can
//! contain the very values a scan is meant to protect.

use indicatif::{HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    io::IsTerminal,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const PLAIN_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Animated bar on an interactive terminal; periodic lines otherwise.
    Auto,
    Bar,
    Plain,
    Off,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "bar" => Some(Self::Bar),
            "plain" => Some(Self::Plain),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Cheap to clone and safe to share across scanner threads.
#[derive(Clone, Default)]
pub struct Progress(Option<Arc<Inner>>);

struct Inner {
    bar: Option<ProgressBar>,
    started: Instant,
    state: Mutex<State>,
    items: AtomicU64,
    bytes: AtomicU64,
}

struct State {
    phase: String,
    scan_started: Option<Instant>,
    total_items: u64,
    total_bytes: u64,
    last_plain: Option<Instant>,
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg} [{elapsed}]")
        .expect("static progress template")
}

fn bytes_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} Scanning [{bar:30.cyan/blue}] {percent:>3}% {msg} \
         {binary_bytes}/{binary_total_bytes} · {binary_bytes_per_sec} · ETA {eta}",
    )
    .expect("static progress template")
    .progress_chars("=> ")
}

fn items_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} Scanning [{bar:30.cyan/blue}] {percent:>3}% {msg} · ETA {eta}",
    )
    .expect("static progress template")
    .progress_chars("=> ")
}

impl Progress {
    pub fn new(mode: Mode) -> Self {
        let animated = match mode {
            Mode::Off => return Self(None),
            Mode::Bar => true,
            Mode::Plain => false,
            // Terminals that cannot redraw lines (e.g. TERM=dumb) get periodic lines instead.
            Mode::Auto => {
                std::io::stderr().is_terminal()
                    && std::env::var("TERM").is_ok_and(|term| !term.is_empty() && term != "dumb")
            }
        };
        let bar = animated.then(|| {
            let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(8));
            bar.set_style(spinner_style());
            bar.set_message("Starting");
            bar.enable_steady_tick(Duration::from_millis(120));
            bar
        });
        Self(Some(Arc::new(Inner {
            bar,
            started: Instant::now(),
            state: Mutex::new(State {
                phase: String::new(),
                scan_started: None,
                total_items: 0,
                total_bytes: 0,
                last_plain: None,
            }),
            items: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        })))
    }

    pub fn disabled() -> Self {
        Self(None)
    }

    /// Starts an indeterminate stage such as enumeration or acquisition.
    pub fn phase(&self, name: &str) {
        let Some(inner) = &self.0 else { return };
        let mut state = inner.state.lock().expect("progress state");
        state.phase = name.into();
        match &inner.bar {
            Some(bar) => bar.set_message(name.to_string()),
            None => {
                state.last_plain = Some(Instant::now());
                eprintln!("SecretHunter: {name}...");
            }
        }
    }

    /// Updates the current indeterminate stage with an internally generated detail.
    pub fn status(&self, detail: &str) {
        let Some(inner) = &self.0 else { return };
        let mut state = inner.state.lock().expect("progress state");
        if state.scan_started.is_some() {
            return;
        }
        let line = format!("{} ({detail})", state.phase);
        match &inner.bar {
            Some(bar) => bar.set_message(line),
            None if due(&mut state) => eprintln!("SecretHunter: {line}"),
            None => {}
        }
    }

    pub fn begin_scan(&self, items: u64, bytes: u64) {
        let Some(inner) = &self.0 else { return };
        let mut state = inner.state.lock().expect("progress state");
        state.scan_started = Some(Instant::now());
        state.total_items = items;
        state.total_bytes = bytes;
        state.last_plain = Some(Instant::now());
        inner.items.store(0, Ordering::Relaxed);
        inner.bytes.store(0, Ordering::Relaxed);
        match &inner.bar {
            Some(bar) => {
                bar.set_style(if bytes > 0 {
                    bytes_style()
                } else {
                    items_style()
                });
                bar.set_length(if bytes > 0 { bytes } else { items.max(1) });
                bar.set_position(0);
                bar.reset_eta();
                bar.set_message(format!("0/{items} objects"));
            }
            None => eprintln!(
                "SecretHunter: scanning {items} objects ({})...",
                HumanBytes(bytes)
            ),
        }
    }

    pub fn advance(&self, items: u64, bytes: u64) {
        let Some(inner) = &self.0 else { return };
        let done_items = inner.items.fetch_add(items, Ordering::Relaxed) + items;
        let done_bytes = inner.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let mut state = inner.state.lock().expect("progress state");
        if state.scan_started.is_none() {
            return;
        }
        match &inner.bar {
            Some(bar) => {
                bar.set_position(if state.total_bytes > 0 {
                    done_bytes.min(state.total_bytes)
                } else {
                    done_items
                });
                bar.set_message(format!("{done_items}/{} objects", state.total_items));
            }
            None if due(&mut state) => eprintln!("SecretHunter: {}", plain_line(inner, &state)),
            None => {}
        }
    }

    /// Emits a heartbeat in plain mode even while a single large object is inspected.
    pub fn tick(&self) {
        let Some(inner) = &self.0 else { return };
        if inner.bar.is_some() {
            return;
        }
        let mut state = inner.state.lock().expect("progress state");
        if state.scan_started.is_some() && due(&mut state) {
            eprintln!("SecretHunter: {}", plain_line(inner, &state));
        }
    }

    pub fn finish(&self, summary: &str) {
        let Some(inner) = &self.0 else { return };
        if let Some(bar) = &inner.bar {
            bar.finish_and_clear();
        }
        eprintln!(
            "SecretHunter: {summary} in {}.",
            HumanDuration(inner.started.elapsed())
        );
    }
}

fn due(state: &mut State) -> bool {
    let now = Instant::now();
    if state
        .last_plain
        .is_some_and(|last| now.duration_since(last) < PLAIN_INTERVAL)
    {
        return false;
    }
    state.last_plain = Some(now);
    true
}

fn plain_line(inner: &Inner, state: &State) -> String {
    let items = inner.items.load(Ordering::Relaxed);
    let bytes = inner.bytes.load(Ordering::Relaxed).min(state.total_bytes);
    let (done, total) = if state.total_bytes > 0 {
        (bytes, state.total_bytes)
    } else {
        (items, state.total_items.max(1))
    };
    let fraction = done as f64 / total as f64;
    let elapsed = state.scan_started.map_or(Duration::ZERO, |s| s.elapsed());
    let remaining = if done > 0 && done < total {
        let seconds = elapsed.as_secs_f64() * (1.0 - fraction) / fraction;
        format!(
            ", about {} remaining",
            HumanDuration(Duration::from_secs_f64(seconds))
        )
    } else {
        String::new()
    };
    format!(
        "scanning {:.0}% ({items}/{} objects, {} of {}), elapsed {}{remaining}",
        fraction * 100.0,
        state.total_items,
        HumanBytes(bytes),
        HumanBytes(state.total_bytes),
        HumanDuration(elapsed),
    )
}

pub fn human_bytes(bytes: u64) -> String {
    HumanBytes(bytes).to_string()
}
