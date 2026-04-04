#[macro_export]
macro_rules! pr_err {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        unsafe { if DEBUG_LEVEL.assume_init() >= 1 {
            eprintln!("{}", "ERROR:".red().bold());
            eprintln!($($arg)*);
        } }
    }};
}

#[macro_export]
macro_rules! pr_warn {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        unsafe { if DEBUG_LEVEL.assume_init() >= 2 {
            eprintln!("{}", "WARNING:".yellow().bold());
            eprintln!($($arg)*);
        } }
    }};
}

#[macro_export]
macro_rules! pr_info {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        unsafe { if DEBUG_LEVEL.assume_init() >= 3 {
            println!("{}", "INFO:".blue().bold());
            println!($($arg)*);
        } }
    }};
}

#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        unsafe { if DEBUG_LEVEL.assume_init() >= 4 {
            println!("{}", "DEBUG:".green().bold());
            println!($($arg)*);
        } }
    }};
}
