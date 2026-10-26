use directories::UserDirs;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Setup function for setting up the Log4rs logging configuring it
/// for all the different modules and and setting up file and stdout logging
pub fn setup() {
    let user_dirs = UserDirs::new().expect("failed to get user dir");
    let doc_dir = user_dirs
        .document_dir()
        .expect("Failed to get document dir");

    unsafe { std::env::set_var("RUST_LOG", "debug") };

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(format!("debug",)));

    let stdout_layer = fmt::layer().with_target(true).with_ansi(true);

    let file_appender = tracing_appender::rolling::never(doc_dir, "pocket-ark-dump.log");
    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);
    Box::leak(Box::new(_guard));

    let file_layer = fmt::layer()
        .with_writer(non_blocking_file)
        .with_target(true)
        .with_ansi(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .init();

    log_panics::init();
}
