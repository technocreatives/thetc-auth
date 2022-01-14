mod postgres;

use async_trait::async_trait;
use secrecy::Secret;

use crate::{
    password_strategy::Strategy,
    username::{Username, UsernameType},
};

#[nova::newtype(serde, sqlx, copy, new)]
pub type UserId = uuid::Uuid;

pub type PgUsers<S, U> = postgres::Backend<S, U>;

#[derive(Debug)]
pub struct NewUser<U: UsernameType> {
    pub username: Username<U>,
    pub password: Secret<String>,
    pub meta: serde_json::Value,
    pub id: Option<UserId>,
}

impl<U: UsernameType> NewUser<U> {
    pub fn new(username: &str, password: &str) -> Result<Self, U::Err> {
        Ok(Self {
            username: username.parse()?,
            password: Secret::new(password.to_string()),
            meta: Default::default(),
            id: None,
        })
    }

    pub fn with_id(id: UserId, username: &str, password: &str) -> Result<Self, U::Err> {
        Ok(Self {
            username: username.parse()?,
            password: Secret::new(password.to_string()),
            meta: Default::default(),
            id: Some(id),
        })
    }
}

#[derive(Debug)]
pub struct User<U: UsernameType> {
    pub id: UserId,
    pub username: Username<U>,
    pub password_hash: Secret<String>,
    pub meta: serde_json::Value,
}

impl<U: UsernameType> User<U> {
    pub fn new(
        id: UserId,
        username: &str,
        password_hash: String,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, U::TryIntoError> {
        let username: Username<U> = username.parse()?;

        Ok(Self {
            id,
            username,
            password_hash: Secret::new(password_hash),
            meta: meta.unwrap_or(serde_json::Value::Null),
        })
    }
}

#[async_trait]
pub trait UserBackend<S: Strategy, U: UsernameType> {
    type Error: std::error::Error;

    async fn create_user(&self, user: NewUser<U>) -> Result<User<U>, Self::Error>;
    async fn find_user_by_id(&self, id: UserId) -> Result<User<U>, Self::Error>;
    async fn find_user_by_username(&self, name: &str) -> Result<User<U>, Self::Error>;
    fn verify_password(&self, user: &User<U>, password: &str) -> Result<(), Self::Error>;
}
