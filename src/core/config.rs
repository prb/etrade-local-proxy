//! Pure config validation over a snapshot of the environment captured by the
//! shell, so validation (AC-11) is unit-testable without touching real env
//! vars. Empty strings are treated as missing.

use crate::core::error::ConfigError;
use crate::core::newtypes::{ConsumerKey, ConsumerSecret, ListenPort};

/// A snapshot of the two credential environment variables, captured once by
/// `shell::env`. `None` means the variable was unset; an empty string means it
/// was set but blank (treated as missing by [`build_config`]).
#[derive(Debug, Default, Clone)]
pub struct EnvSnapshot {
    pub consumer_key: Option<String>,
    pub consumer_secret: Option<String>,
}

/// The validated runtime configuration.
#[derive(Debug)]
pub struct Config {
    consumer_key: ConsumerKey,
    consumer_secret: ConsumerSecret,
    port: ListenPort,
}

impl Config {
    pub fn consumer_key(&self) -> &ConsumerKey {
        &self.consumer_key
    }

    pub fn consumer_secret(&self) -> &ConsumerSecret {
        &self.consumer_secret
    }

    pub fn port(&self) -> ListenPort {
        self.port
    }
}

/// Validate an [`EnvSnapshot`] plus the chosen port into a [`Config`]. Missing
/// or empty credential variables yield a typed [`ConfigError`] naming the
/// variable (never the value).
pub fn build_config(env: &EnvSnapshot, port: ListenPort) -> Result<Config, ConfigError> {
    let consumer_key = non_empty(env.consumer_key.as_deref())
        .ok_or_else(|| classify(env.consumer_key.as_deref(), Credential::Key))?;
    let consumer_secret = non_empty(env.consumer_secret.as_deref())
        .ok_or_else(|| classify(env.consumer_secret.as_deref(), Credential::Secret))?;

    Ok(Config {
        consumer_key: ConsumerKey::new(consumer_key),
        consumer_secret: ConsumerSecret::new(consumer_secret),
        port,
    })
}

/// Returns the value only if it is present and non-empty after trimming.
fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

enum Credential {
    Key,
    Secret,
}

/// Pick the precise error: unset => Missing*, present-but-blank => Empty*.
fn classify(value: Option<&str>, which: Credential) -> ConfigError {
    match (value, which) {
        (None, Credential::Key) => ConfigError::MissingConsumerKey,
        (Some(_), Credential::Key) => ConfigError::EmptyConsumerKey,
        (None, Credential::Secret) => ConfigError::MissingConsumerSecret,
        (Some(_), Credential::Secret) => ConfigError::EmptyConsumerSecret,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn port() -> ListenPort {
        ListenPort::new(8443)
    }

    #[test]
    fn valid_config_builds() {
        let env = EnvSnapshot {
            consumer_key: Some("ckey".into()),
            consumer_secret: Some("csec".into()),
        };
        let config = build_config(&env, port()).unwrap();
        assert_eq!(config.consumer_key().as_str(), "ckey");
        assert_eq!(config.consumer_secret().secret().expose_secret(), "csec");
        assert_eq!(config.port().get(), 8443);
    }

    #[test]
    fn missing_key_rejected() {
        let env = EnvSnapshot {
            consumer_key: None,
            consumer_secret: Some("csec".into()),
        };
        assert_eq!(
            build_config(&env, port()).unwrap_err(),
            ConfigError::MissingConsumerKey
        );
    }

    #[test]
    fn empty_key_rejected() {
        let env = EnvSnapshot {
            consumer_key: Some("   ".into()),
            consumer_secret: Some("csec".into()),
        };
        assert_eq!(
            build_config(&env, port()).unwrap_err(),
            ConfigError::EmptyConsumerKey
        );
    }

    #[test]
    fn missing_secret_rejected() {
        let env = EnvSnapshot {
            consumer_key: Some("ckey".into()),
            consumer_secret: None,
        };
        assert_eq!(
            build_config(&env, port()).unwrap_err(),
            ConfigError::MissingConsumerSecret
        );
    }

    #[test]
    fn empty_secret_rejected() {
        let env = EnvSnapshot {
            consumer_key: Some("ckey".into()),
            consumer_secret: Some("".into()),
        };
        assert_eq!(
            build_config(&env, port()).unwrap_err(),
            ConfigError::EmptyConsumerSecret
        );
    }

    #[test]
    fn error_messages_name_variable_not_value() {
        let msg = ConfigError::MissingConsumerKey.to_string();
        assert!(msg.contains("ETRADE_CONSUMER_KEY"));
    }
}
