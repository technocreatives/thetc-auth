use std::{cell::RefCell, collections::HashMap};

use chrono::{DateTime, Utc};

use super::SessionId;

pub type SessionManager<U> = super::SessionManager<Backend<U>, Session<U>, U, Error>;

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
