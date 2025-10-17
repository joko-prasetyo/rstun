#[macro_export]
macro_rules! log_and_bail {
    ($($args:tt)*) => {
        log::error!($($args)*);
        anyhow::bail!(format!($($args)*));
    };
}

#[macro_export]
macro_rules! unwrap_or_continue {
    ($opt:ident) => {
        if let Some(value) = $opt {
            value
        } else {
            continue;
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($e:expr, $r:expr) => {
        match $e {
            Some(e) => e,
            None => return $r,
        }
    };
}
