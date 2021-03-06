use std::marker::PhantomData;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{PasswordResetId, SessionId};

pub type SessionManager<U> = super::SessionManager<Backend<U>, Session<U>, U, Error>;

pub struct Backend<U> {
    _user_ty: PhantomData<U>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {}

#[async_trait]
impl<U: sqlx::Type<sqlx::Postgres> + Send + Sync> super::SessionBackend for Backend<U> {
    type Error = Error;
    type UserId = U;
    type Session = Session<Self::UserId>;

    async fn new_session(
        &self,
        id: Self::UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        todo!()
    }

    async fn clear_stale_sessions(&self) -> Result<(), Self::Error> {
        todo!()
    }

    async fn expire(&self, session: Self::Session) -> Result<(), Self::Error> {
        todo!()
    }

    async fn extend_expiry_date(
        &self,
        session: Self::Session,
        expires_at: DateTime<Utc>,
    ) -> Result<Self::Session, Self::Error> {
        todo!()
    }

    async fn session(
        &self,
        id: SessionId,
        extend_expiry: Option<DateTime<Utc>>,
    ) -> Result<Self::Session, Self::Error> {
        todo!()
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
        todo!();
    }

    async fn consume_password_reset_id(
        &self,
        id: PasswordResetId,
    ) -> Result<Self::UserId, Self::Error> {
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
