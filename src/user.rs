mod postgres;

use async_trait::async_trait;
use secrecy::Secret;

use crate::{
    password_strategy::Strategy,
    username::{Username, UsernameType},
};

#[nova::newtype(serde, sqlx, copy)]
pub type UserId = uuid::Uuid;

pub type PgUsers<S, U> = postgres::Backend<S, U>;

#[derive(Debug)]
pub struct NewUser<U: UsernameType> {
    pub username: Username<U>,
    pub password: Secret<String>,
    pub meta: serde_json::Value,
}

impl<U: UsernameType> NewUser<U> {
    pub fn new(username: &str, password: &str) -> Result<Self, U::Err> {
        Ok(Self {
            username: username.parse()?,
            password: Secret::new(password.to_string()),
            meta: Default::default(),
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

#[async_trait(?Send)]
pub trait UserBackend<S: Strategy, U: UsernameType> {
    type Error;

    async fn create_user(&self, user: NewUser<U>) -> Result<User<U>, Self::Error>;
    async fn find_user_by_id(&self, id: UserId) -> Result<User<U>, Self::Error>;
    async fn find_user_by_username(&self, name: &str) -> Result<User<U>, Self::Error>;
}
