use std::fmt::Display;

use chrono::{DateTime, Utc};

pub mod memory;
pub mod postgres;

pub trait SessionBackend {
    type Error;
    type Session;
    type UserId;

    fn new_session(
        &self,
        id: Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error>;
    fn session(&self, id: SessionId) -> Result<Option<Self::Session>, Self::Error>;
    fn clear_stale_sessions(&self) -> Result<(), Self::Error>;
    fn expire(&self, session: Self::Session) -> Result<(), Self::Error>;
    fn extend_expiry_date(
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
    pub fn extend_expiry_date(&self, session: S) -> Result<S, E> {
        let expires_at = Utc::now() + self.alive_duration;
        self.backend.extend_expiry_date(session, expires_at)
    }

    #[inline]
    pub fn new_session(&self, user_id: U) -> Result<S, E> {
        let expires_at = Utc::now() + self.alive_duration;
        self.backend.new_session(user_id, expires_at)
    }

    #[inline]
    pub fn session(&self, session_id: SessionId) -> Result<Option<S>, E> {
        let session = self.backend.session(session_id);
        if self.auto_refresh {
            if let Ok(Some(session)) = session {
                let expires_at = Utc::now() + self.alive_duration;
                return Ok(Some(self.backend.extend_expiry_date(session, expires_at)?));
            }
        }
        session
    }

    #[inline]
    fn clear_stale_sessions(&self) -> Result<(), E> {
        self.backend.clear_stale_sessions()
    }

    #[inline]
    fn expire(&self, session: S) -> Result<(), E> {
        self.backend.expire(session)
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
        let handler =
            memory::SessionManager::new(true, Duration::seconds(5), memory::Backend::default());
        let user_id = UserId::random();
        let session = handler.new_session(user_id).unwrap();
        let _mm = handler.session(session.id).unwrap().unwrap();
    }

    #[test]
    fn memory_expired_session() {
        let handler =
            memory::SessionManager::new(true, Duration::seconds(-1), memory::Backend::default());
        let user_id = UserId::random();
        let session = handler.new_session(user_id).unwrap();
        assert!(handler.session(session.id).unwrap().is_none())
    }
}
