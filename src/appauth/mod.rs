pub mod postgres_redis;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::Secret;

#[nova::newtype(serde, sqlx, copy, new)]
pub type AppAuthId = uuid::Uuid;

#[derive(Debug)]
pub struct NewAppAuth {
    pub name: String,
    pub description: Option<String>,
    pub token: Secret<String>,
    pub meta: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AppAuth {
    pub id: AppAuthId,
    pub name: String,
    pub description: Option<String>,
    pub token: Secret<String>,
    pub meta: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait AppAuthBackend {
    type Error: std::error::Error;

    async fn create_appauth(&self, app_auth: NewAppAuth) -> Result<AppAuth, Self::Error>;
    // async fn find_appauth_by_id(&self, id: AppAuthId) -> Result<AppAuth, Self::Error>;
    async fn verify_token(&self, id: AppAuthId, token: &str) -> Result<(), Self::Error>;
}
