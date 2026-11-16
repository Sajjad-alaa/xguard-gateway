use thiserror::Error;
use xguard_version::{SemverError, XGuardVersionError};
use xguard_wireguard_rs::error::WireguardInterfaceError;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Command {command} execution failed. Error: {error}")]
    CommandExecutionFailed { command: String, error: String },

    #[error("Logger error")]
    Logger(#[from] log::SetLoggerError),

    #[error("Syslog error")]
    Syslog(#[from] syslog::Error),

    #[error("Tonic error")]
    Tonic(#[from] tonic::transport::Error),

    #[error("Invalid config file. Error: {0}")]
    InvalidConfigFile(String),

    #[error("WireGuard error: {0}")]
    WireguardError(#[from] WireguardInterfaceError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    XGuardVersionError(#[from] XGuardVersionError),

    #[error(transparent)]
    SemverError(#[from] SemverError),

    #[error("Encountered an error during Gateway setup: {0}")]
    SetupError(String),
}
