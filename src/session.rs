use std::fmt::Display;

use chrono::{DateTime, Utc};

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

pub struct SessionHandler<T, S, U, E>
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

impl<T, S, U, E> SessionHandler<T, S, U, E>
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

pub mod postgres {
    use std::marker::PhantomData;

    use chrono::{DateTime, Utc};

    use super::SessionId;

    pub type SessionHandler<U> = super::SessionHandler<Backend<U>, Session<U>, U, Error>;

    pub struct Backend<U> {
        _user_ty: PhantomData<U>,
    }

    pub enum Error {}

    impl<U: sqlx::Type<sqlx::Postgres>> super::SessionBackend for Backend<U> {
        type Error = Error;
        type UserId = U;
        type Session = Session<Self::UserId>;

        fn new_session(
            &self,
            id: Self::UserId,
            expires_at: DateTime<Utc>,
        ) -> Result<Self::Session, Self::Error> {
            todo!()
        }

        fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
            todo!()
        }

        fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
            todo!()
        }

        fn extend_expiry_date(
            &self,
            session: Self::Session,
            expires_at: DateTime<Utc>,
        ) -> Result<Self::Session, Self::Error> {
            todo!()
        }

        fn session(&self, id: SessionId) -> Result<Option<Self::Session>, Self::Error> {
            todo!()
        }
    }

    pub struct Session<U: sqlx::Type<sqlx::Postgres>> {
        id: SessionId,
        user_id: U,
        data: serde_json::Value,
        expires_at: chrono::DateTime<chrono::Utc>,
    }

    struct NewSession<U: sqlx::Type<sqlx::Postgres>> {
        id: SessionId,
        user_id: U,
    }
}

pub mod memory {
    use std::{cell::RefCell, collections::HashMap};

    use chrono::{DateTime, Utc};

    use super::SessionId;

    pub type SessionHandler<U> = super::SessionHandler<Backend<U>, Session<U>, U, Error>;

    #[derive(Debug, Clone)]
    pub struct Session<U: Clone> {
        pub id: SessionId,
        pub user_id: U,
        pub expires_at: DateTime<Utc>,
    }

    #[derive(Debug)]
    pub struct Backend<U: Clone> {
        sessions: RefCell<HashMap<SessionId, Session<U>>>,
    }

    impl<U: Clone> Default for Backend<U> {
        fn default() -> Self {
            Self {
                sessions: RefCell::new(HashMap::new()),
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("Session not found for given id {0}")]
        NotFound(SessionId),
    }

    impl<U: Clone> super::SessionBackend for Backend<U> {
        type Error = Error;
        type Session = Session<U>;
        type UserId = U;

        fn new_session(
            &self,
            user_id: Self::UserId,
            expires_at: DateTime<Utc>,
        ) -> Result<Self::Session, Self::Error> {
            let mut guard = self.sessions.borrow_mut();
            let id = SessionId::new();
            let session = Session {
                id,
                user_id,
                expires_at,
            };
            guard.insert(id, session.clone());
            Ok(session)
        }

        fn session(&self, id: SessionId) -> Result<Option<Self::Session>, Self::Error> {
            let mut guard = self.sessions.borrow_mut();
            Ok(match guard.get(&id).cloned() {
                Some(v) => {
                    if Utc::now() < v.expires_at {
                        Some(v)
                    } else {
                        // Remove because expired.
                        guard.remove(&id);
                        None
                    }
                }
                None => None,
            })
        }

        fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
            let keys = {
                let guard = self.sessions.borrow();
                guard
                    .iter()
                    .filter(|(k, v)| Utc::now() >= v.expires_at)
                    .map(|(k, _)| k)
                    .copied()
                    .collect::<Vec<_>>()
            };

            let mut guard = self.sessions.borrow_mut();
            for key in keys {
                guard.remove(&key);
            }

            Ok(())
        }

        fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
            let mut guard = self.sessions.borrow_mut();
            guard.remove(&session.id);
            Ok(())
        }

        fn extend_expiry_date(
            &self,
            session: Self::Session,
            expires_at: DateTime<Utc>,
        ) -> Result<Self::Session, Self::Error> {
            let mut guard = self.sessions.borrow_mut();
            let session = guard
                .get_mut(&session.id)
                .ok_or_else(|| Error::NotFound(session.id))?;
            session.expires_at = expires_at;
            Ok(session.clone())
        }
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
            memory::SessionHandler::new(true, Duration::seconds(5), memory::Backend::default());
        let user_id = UserId::random();
        let session = handler.new_session(user_id).unwrap();
        let _mm = handler.session(session.id).unwrap().unwrap();
    }

    #[test]
    fn memory_expired_session() {
        let handler =
            memory::SessionHandler::new(true, Duration::seconds(-1), memory::Backend::default());
        let user_id = UserId::random();
        let session = handler.new_session(user_id).unwrap();
        assert!(handler.session(session.id).unwrap().is_none())
    }
}
