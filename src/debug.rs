//! Print log messages at the chosen level.
//!
//! The macros take format arguments and write to stdout or stderr.
//! [`crate::debugs_or!`] picks a full error or a short error. The main thread sets
//! [`crate::DEBUG_LEVEL`] before rayon starts, so worker threads only read it.
//! These logs help diagnose a failed link; [`crate::report`] shows ELF stage results.
//!
//! Reference: [GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html)
//! gives the context for linker diagnostics; these macros use our own log format.

/// Use full error details at level four and short text at lower levels.
#[macro_export]
macro_rules! debugs_or {
    ($debug:expr, $normal:expr) => {{
        #[allow(unused_unsafe)]
        unsafe {
            if crate::DEBUG_LEVEL.assume_init() >= 4 {
                $debug
            } else {
                $normal
            }
        }
    }};
}

/// Print to stderr at level one or higher.
#[macro_export]
macro_rules! pr_err {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        #[allow(unused_unsafe)]
        unsafe { if crate::DEBUG_LEVEL.assume_init() >= 1 {
            eprintln!("{}", "ERROR:".red().bold());
            eprintln!($($arg)*);
        } }
    }};
}

/// Print to stderr at level two or higher.
#[macro_export]
macro_rules! pr_warn {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        #[allow(unused_unsafe)]
        unsafe { if crate::DEBUG_LEVEL.assume_init() >= 2 {
            eprintln!("{}", "WARNING:".yellow().bold());
            eprintln!($($arg)*);
        } }
    }};
}

/// Print progress to stdout at level three or higher.
#[macro_export]
macro_rules! pr_info {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        #[allow(unused_unsafe)]
        unsafe { if crate::DEBUG_LEVEL.assume_init() >= 3 {
            println!("{}", "INFO:".blue().bold());
            println!($($arg)*);
        } }
    }};
}

/// Print details to stdout at level four or higher.
#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        #[allow(unused_unsafe)]
        unsafe { if crate::DEBUG_LEVEL.assume_init() >= 4 {
            println!("{}", "DEBUG:".green().bold());
            println!($($arg)*);
        } }
    }};
}
