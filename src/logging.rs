use super::{log, Config};
use fern;

pub(crate) fn setup_logger(config: &Config) -> Result<(), fern::InitError> {
    let self_level;
    let default_level;
    let file_level;

    match config.debug {
        0 => {
            self_level = log::LevelFilter::Warn;
            default_level = log::LevelFilter::Warn;
            file_level = log::LevelFilter::Warn;
        }
        1 => {
            self_level = log::LevelFilter::Warn;
            default_level = log::LevelFilter::Warn;
            file_level = log::LevelFilter::Debug;
        }
        _ => {
            self_level = log::LevelFilter::Debug;
            default_level = log::LevelFilter::Debug;
            file_level = log::LevelFilter::Debug;
        }
    }

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(default_level)
        .level_for("tail-stack-events", self_level)
        .chain(std::io::stdout())
        .chain(
            fern::Dispatch::new()
                .chain(fern::log_file("output.log")?)
                .level(file_level),
        )
        .apply()?;
    Ok(())
}
