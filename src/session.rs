use std::{convert::TryFrom, fmt::Display, ops::Deref};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod memory;
pub mod postgres;
pub mod redis;

#[async_trait]
pub trait SessionBackend: Send + Sync {
    type Error: std::error::Error;
    type Session;
    type UserId;

    async fn new_session(
        &self,
        id: Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error>;
    async fn session(
        &self,
        id: SessionId,
        extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error>;
    async fn clear_stale_sessions(&self) -> Result<(), Self::Error>;
    async fn expire(&self, session: Self::Session) -> Result<(), Self::Error>;
    async fn extend_expiry_date(
        &self,
        session: Self::Session,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error>;
}

#[nova::newtype(sqlx, serde, copy)]
pub type SessionId = uuid::Uuid;

impl SessionId {
    pub fn new() -> Self {
        SessionId(uuid::Uuid::new_v4())
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&**self, f)
    }
}

impl TryFrom<&str> for SessionId {
    type Error = uuid::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let uuid = uuid::Uuid::parse_str(value)?;
        Ok(Self(uuid))
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        <SessionId as TryFrom<&str>>::try_from(&value)
    }
}

pub struct SessionManager<T, S, U, E>
where
    T: SessionBackend<Error = E, Session = S, UserId = U>,
{
    /// Session automatically refreshes expires_at date upon access.
    auto_refresh: bool,

    /// Duration before session expires.
    alive_duration: chrono::Duration,

    /// Session backend abstraction.
    backend: T,
}

impl<T, S, U, E> SessionManager<T, S, U, E>
where
    T: SessionBackend<Error = E, Session = S, UserId = U>,
{
    pub fn new(auto_refresh: bool, alive_duration: chrono::Duration, backend: T) -> Self {
        Self {
            auto_refresh,
            alive_duration,
            backend,
        }
    }

    #[inline]
    pub async fn extend_expiry_date(&self, session: S) -> Result<S, E> {
        let expires_at = Utc::now() + self.alive_duration;
        self.backend.extend_expiry_date(session, expires_at).await
    }

    #[inline]
    pub async fn new_session(&self, user_id: U) -> Result<S, E> {
        let expires_at = Utc::now() + self.alive_duration;
        self.backend.new_session(user_id, expires_at).await
    }

    #[inline]
    pub async fn session(&self, session_id: SessionId) -> Result<S, E> {
        let extend_expiry = match self.auto_refresh {
            true => Some(Utc::now() + self.alive_duration),
            false => None,
        };

        self.backend.session(session_id, extend_expiry).await
    }

    #[inline]
    pub async fn clear_stale_sessions(&self) -> Result<(), E> {
        self.backend.clear_stale_sessions().await
    }

    #[inline]
    pub async fn expire(&self, session: S) -> Result<(), E> {
        self.backend.expire(session).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[nova::newtype(copy)]
    type UserId = uuid::Uuid;

    impl UserId {
        fn random() -> Self {
            UserId(uuid::Uuid::new_v4())
        }
    }

    #[test]
    fn memory() {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async move {
            let handler =
                memory::SessionManager::new(true, Duration::seconds(5), memory::Backend::default());
            let user_id = UserId::random();
            let session = handler.new_session(user_id).await.unwrap();
            let _mm = handler.session(session.id).await.unwrap();
        })
    }

    #[test]
    fn memory_expired_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let handler = memory::SessionManager::new(
                true,
                Duration::seconds(-1),
                memory::Backend::default(),
            );
            let user_id = UserId::random();
            let session = handler.new_session(user_id).await.unwrap();
            assert!(handler.session(session.id).await.is_err())
        });
    }
}
