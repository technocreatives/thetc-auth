use std::{collections::HashMap, sync::RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{PasswordResetId, SessionId};

pub type SessionManager<U> = super::SessionManager<Backend<U>, Session<U>, U, Error>;

#[derive(Debug, Clone)]
pub struct Session<U: Clone> {
    pub id: SessionId,
    pub user_id: U,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Backend<U: Clone> {
    sessions: RwLock<HashMap<SessionId, Session<U>>>,
}

impl<U: Clone> Default for Backend<U> {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Session not found for given id {0}")]
    NotFound(SessionId),
}

#[async_trait]
impl<U: Clone + Send + Sync> super::SessionBackend for Backend<U> {
    type Error = Error;
    type Session = Session<U>;
    type UserId = U;

    async fn new_session(
        &self,
        user_id: Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        let id = SessionId::new();
        let session = Session {
            id,
            user_id,
            expires_at,
        };
        guard.insert(id, session.clone());
        Ok(session)
    }

    async fn session(
        &self,
        id: SessionId,
        extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        Ok(match guard.get(&id).cloned() {
            Some(v) => {
                if Utc::now() < v.expires_at {
                    v
                } else {
                    // Remove because expired.
                    guard.remove(&id);
                    return Err(Error::NotFound(id));
                }
            }
            None => return Err(Error::NotFound(id)),
        })
    }

    async fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
        let keys = {
            let guard = self.sessions.read().unwrap();
            guard
                .iter()
                .filter(|(k, v)| Utc::now() >= v.expires_at)
                .map(|(k, _)| k)
                .copied()
                .collect::<Vec<_>>()
        };

        let mut guard = self.sessions.write().unwrap();
        for key in keys {
            guard.remove(&key);
        }

        Ok(())
    }

    async fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        guard.remove(&session.id);
        Ok(())
    }

    async fn extend_expiry_date(
        &self,
        session: Self::Session,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        let mut guard = self.sessions.write().unwrap();
        let session = guard
            .get_mut(&session.id)
            .ok_or_else(|| Error::NotFound(session.id))?;
        session.expires_at = expires_at;
        Ok(session.clone())
    }

    async fn generate_password_reset_id(
        &self,
        id: Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetId, Self::Error> {
        todo!()
    }

    async fn verify_password_reset_id(
        &self,
        id: PasswordResetId,
    ) -> Result<Self::UserId, Self::Error> {
        todo!()
    }

    async fn consume_password_reset_id(
        &self,
        id: PasswordResetId,
    ) -> Result<Self::UserId, Self::Error> {
        todo!()
    }
}
