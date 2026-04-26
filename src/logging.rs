//! Minimal logging: a single global `verbose` flag + macros.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

#[inline]
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! vlog {
    ($($t:tt)*) => {{
        if $crate::logging::verbose() {
            eprintln!($($t)*);
        }
    }};
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => {{ eprintln!($($t)*); }};
}
