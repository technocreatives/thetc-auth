use std::marker::PhantomData;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sqlx::PgPool;

use crate::{password_strategy::Strategy, username::UsernameType};

use super::{NewUser, User, UserBackend, UserId};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),

    #[error("password error")]
    Password(#[from] crate::password_strategy::Error),

    #[error("The entered password was invalid.")]
    InvalidPassword,
}

pub struct Backend<S: Strategy, U: UsernameType> {
    strategy: S,
    pool: PgPool,
    table_name: &'static str,
    _username: PhantomData<U>,
}

impl<S: Strategy, U: UsernameType> Backend<S, U> {
    pub fn new(pool: PgPool, table_name: &'static str, strategy: S) -> Self {
        Self {
            strategy,
            pool,
            table_name,
            _username: PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<S: Strategy, U: UsernameType> UserBackend<S, U> for Backend<S, U> {
    type Error = Error;

    async fn create_user(&self, user: NewUser<U>) -> Result<User<U>, Self::Error> {
        let password_hash = self
            .strategy
            .generate_password_hash(user.password.expose_secret())?;
        let mut conn = self.pool.begin().await?;
        let user_id = match user.id {
            Some(id) => {
                database::insert_user_with_id(
                    &mut conn,
                    id,
                    user.username,
                    password_hash,
                    user.meta,
                    self.table_name,
                )
                .await?
            }
            None => {
                database::insert_user(
                    &mut conn,
                    user.username,
                    password_hash,
                    user.meta,
                    self.table_name,
                )
                .await?
            }
        };
        let user = database::find_user_by_id(&mut conn, user_id, self.table_name).await?;
        conn.commit().await?;
        Ok(user)
    }

    async fn find_user_by_id(&self, id: UserId) -> Result<User<U>, Self::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(database::find_user_by_id(&mut conn, id, self.table_name).await?)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<User<U>, Self::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(
            database::find_user_by_username(&mut conn, username.to_string(), self.table_name)
                .await?,
        )
    }

    fn verify_password(&self, user: &User<U>, password: &str) -> Result<(), Self::Error> {
        match self
            .strategy
            .verify_password(user.password_hash.expose_secret(), password)?
        {
            true => Ok(()),
            false => Err(Error::InvalidPassword),
        }
    }
}

mod database {
    use secrecy::{ExposeSecret, Secret};
    use sqlx::{PgConnection, Row};

    use crate::username::{Username, UsernameType};

    use super::{User, UserId};

    pub async fn insert_user_with_id<U: UsernameType>(
        conn: &mut PgConnection,
        id: UserId,
        username: Username<U>,
        password_hash: Secret<String>,
        meta: serde_json::Value,
        table_name: &'static str,
    ) -> Result<UserId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(id, username, password_hash, meta) VALUES ($1, $2::text, $3, $4)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(*id)
        .bind(&*username)
        .bind(password_hash.expose_secret())
        .bind(meta)
        .fetch_one(conn)
        .await?;

        Ok(UserId(rec.get(0)))
    }

    pub async fn insert_user<U: UsernameType>(
        conn: &mut PgConnection,
        username: Username<U>,
        password_hash: Secret<String>,
        meta: serde_json::Value,
        table_name: &'static str,
    ) -> Result<UserId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(username, password_hash, meta) VALUES ($1::text, $2, $3)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(&*username)
        .bind(password_hash.expose_secret())
        .bind(meta)
        .fetch_one(conn)
        .await?;

        Ok(UserId(rec.get(0)))
    }

    pub async fn find_user_by_id<U: UsernameType>(
        conn: &mut PgConnection,
        id: UserId,
        table_name: &'static str,
    ) -> Result<User<U>, sqlx::Error> {
        let r = sqlx::query(&format!(
            r#"
                SELECT
                    id as "id: UserId",
                    username::TEXT,
                    password_hash,
                    meta
                FROM {}
                WHERE id = $1
                LIMIT 1;
            "#,
            table_name
        ))
        .bind(*id)
        .fetch_one(conn)
        .await?;

        let raw_username: String = r.get(1);
        let username: Username<U> = match raw_username.parse() {
            Ok(v) => v,
            Err(e) => return Err(sqlx::Error::Decode(Box::new(e))),
        };

        Ok(User {
            id: r.get(0),
            username,
            password_hash: Secret::new(r.get(2)),
            meta: r.get(3),
        })
    }

    pub async fn find_user_by_username<U: UsernameType>(
        conn: &mut PgConnection,
        username: String,
        table_name: &'static str,
    ) -> Result<User<U>, sqlx::Error> {
        let r = sqlx::query(&format!(
            r#"
                SELECT
                    id as "id: UserId",
                    username::TEXT,
                    password_hash,
                    meta
                FROM {}
                WHERE username = $1
                LIMIT 1;
            "#,
            table_name
        ))
        .bind(username)
        .fetch_one(conn)
        .await?;

        let raw_username: String = r.get(1);
        let username: Username<U> = match raw_username.parse() {
            Ok(v) => v,
            Err(e) => return Err(sqlx::Error::Decode(Box::new(e))),
        };

        Ok(User {
            id: r.get(0),
            username,
            password_hash: Secret::new(r.get(2)),
            meta: r.get(3),
        })
    }
}
