pub mod ascii;

use std::{fmt::Debug, ops::Deref, str::FromStr};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Username<T: UsernameType>(T);

impl<T: UsernameType + Debug> Debug for Username<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

pub trait UsernameType:
    Deref<Target = str> + FromStr<Err = Self::TryIntoError> + Sync + Send
{
    type TryIntoError: std::error::Error + Send + Sync + 'static;

    fn into_inner(self) -> String;
}

impl<U: UsernameType> FromStr for Username<U> {
    type Err = U::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Username(s.parse()?))
    }
}

impl<T: UsernameType> Deref for Username<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}
