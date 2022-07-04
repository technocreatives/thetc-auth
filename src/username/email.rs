use std::{convert::TryFrom, fmt::Display, hash::Hash, ops::Deref, str::FromStr};

use validator::validate_email;

use super::{Username, UsernameType};

#[derive(Debug, thiserror::Error)]
pub enum TryIntoEmailUsernameError {
    #[error("Username must not be empty string.")]
    Empty,

    #[error("Username is not a valid email")]
    NotValidEmail,

    #[error("Username too long.")]
    UsernameTooLong,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(transparent)]
#[serde(try_from = "String")]
pub struct EmailUsername(String);

impl UsernameType for EmailUsername {
    type TryIntoError = TryIntoEmailUsernameError;

    fn into_inner(self) -> String {
        self.0
    }
}

impl From<EmailUsername> for Username<EmailUsername> {
    fn from(x: EmailUsername) -> Self {
        Self(x)
    }
}

impl FromStr for EmailUsername {
    type Err = TryIntoEmailUsernameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();

        if value.is_empty() {
            return Err(TryIntoEmailUsernameError::Empty);
        }

        if value.len() > 64 {
            return Err(TryIntoEmailUsernameError::UsernameTooLong);
        }

        if !validate_email(value) {
            return Err(TryIntoEmailUsernameError::NotValidEmail);
        }

        Ok(Self(value.to_string()))
    }
}

impl Deref for EmailUsername {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for EmailUsername {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl PartialEq for EmailUsername {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0
            .to_ascii_lowercase()
            .eq(&other.0.to_ascii_lowercase())
    }
}

impl Eq for EmailUsername {}

impl PartialOrd for EmailUsername {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0
            .to_ascii_lowercase()
            .partial_cmp(&other.0.to_ascii_lowercase())
    }
}

impl Ord for EmailUsername {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_ascii_lowercase()
            .cmp(&other.0.to_ascii_lowercase())
    }
}

impl Hash for EmailUsername {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state)
    }
}

impl TryFrom<String> for EmailUsername {
    type Error = <Self as FromStr>::Err;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
