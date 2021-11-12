use std::{convert::TryFrom, fmt::Display, hash::Hash, ops::Deref, str::FromStr};

use super::{Username, UsernameType};

#[derive(Debug, thiserror::Error)]
pub enum TryIntoAsciiUsernameError {
    #[error("Username must not be empty string.")]
    Empty,

    #[error("Non-printable characters found in username.")]
    NonPrintable,

    // It pains me to do this.
    #[error("Non-ASCII characters found in username.")]
    NonAscii,

    #[error("Username too long.")]
    UsernameTooLong,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, sqlx::Type)]
#[sqlx(transparent)]
#[serde(try_from = "String")]
pub struct AsciiUsername(String);

impl UsernameType for AsciiUsername {
    type TryIntoError = TryIntoAsciiUsernameError;

    fn into_inner(self) -> String {
        self.0
    }
}

impl From<AsciiUsername> for Username<AsciiUsername> {
    fn from(x: AsciiUsername) -> Self {
        Self(x)
    }
}

impl FromStr for AsciiUsername {
    type Err = TryIntoAsciiUsernameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();

        if value.len() == 0 {
            return Err(TryIntoAsciiUsernameError::Empty);
        }

        if value.len() > 64 {
            return Err(TryIntoAsciiUsernameError::UsernameTooLong);
        }

        for c in value.chars() {
            if !c.is_ascii() {
                return Err(TryIntoAsciiUsernameError::NonAscii);
            }

            if !c.is_ascii_graphic() {
                return Err(TryIntoAsciiUsernameError::NonPrintable);
            }
        }

        Ok(Self(value.to_string()))
    }
}

impl Deref for AsciiUsername {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for AsciiUsername {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl PartialEq for AsciiUsername {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0
            .to_ascii_lowercase()
            .eq(&other.0.to_ascii_lowercase())
    }
}

impl Eq for AsciiUsername {}

impl PartialOrd for AsciiUsername {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0
            .to_ascii_lowercase()
            .partial_cmp(&other.0.to_ascii_lowercase())
    }
}

impl Ord for AsciiUsername {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_ascii_lowercase()
            .cmp(&other.0.to_ascii_lowercase())
    }
}

impl Hash for AsciiUsername {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state)
    }
}

impl TryFrom<String> for AsciiUsername {
    type Error = <Self as FromStr>::Err;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
