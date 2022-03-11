use async_trait::async_trait;
use deadpool_redis::PoolError;
use redis::RedisError;
use secrecy::ExposeSecret;
use sqlx::PgPool;

use crate::util;

use super::{AppAuth, AppAuthId, NewAppAuth};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "deadpool")]
    #[error("sqlx error")]
    SqlxPool(#[from] deadpool::managed::PoolError<sqlx::Error>),

    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),

    #[error("redis error")]
    RedisPool(#[from] deadpool_redis::PoolError),

    #[error("redis error")]
    Redis(#[from] RedisError),

    // #[error("invalid username")]
    // Username(#[source] Box<dyn std::error::Error + Sync + Send>),
    #[error("The provided token was invalid.")]
    InvalidToken,
}

pub struct Backend {
    pg_pool: PgPool,
    redis_pool: deadpool_redis::Pool,
    table_name: &'static str,
}

impl Backend {
    pub fn new(
        pg_pool: PgPool,
        redis_pool: deadpool_redis::Pool,
        table_name: &'static str,
    ) -> Self {
        Self {
            pg_pool,
            redis_pool,
            table_name,
        }
    }
}

#[cfg(feature = "deadpool")]
pub struct DeadpoolBackend {
    pg_pool: util::deadpool::PgPool,
    redis_pool: deadpool_redis::Pool,
    table_name: &'static str,
}

#[cfg(feature = "deadpool")]
impl DeadpoolBackend {
    pub fn new(
        pg_pool: util::deadpool::PgPool,
        redis_pool: deadpool_redis::Pool,
        table_name: &'static str,
    ) -> Self {
        Self {
            pg_pool,
            redis_pool,
            table_name,
        }
    }
}

async fn set_redis_token(
    redis_pool: &deadpool_redis::Pool,
    appauth: &AppAuth,
) -> Result<(), PoolError> {
    let mut conn = redis_pool.get().await?;
    let mut q = redis::cmd("SET");
    let mut q = q
        .arg(format!("appauth/{}", *appauth.id))
        .arg(appauth.token.expose_secret());

    if let Some(expiry) = appauth.expires_at.as_ref() {
        q = q.arg("EXAT").arg(expiry.timestamp());
    }

    q.query_async(&mut conn).await?;

    Ok(())
}

#[async_trait]
impl super::AppAuthBackend for Backend {
    type Error = Error;

    async fn create_appauth(&self, app_auth: NewAppAuth) -> Result<AppAuth, Self::Error> {
        let mut conn = self.pg_pool.acquire().await?;
        let id = database::insert_app_auth(&mut conn, app_auth, self.table_name).await?;
        let appauth = database::find_appauth_by_id(&mut conn, id, self.table_name).await?;
        set_redis_token(&self.redis_pool, &appauth).await?;

        Ok(appauth)
    }

    async fn verify_token(&self, id: AppAuthId, token: &str) -> Result<(), Self::Error> {
        let mut conn = self.redis_pool.get().await?;

        let redis_token: Option<String> = redis::cmd("GET")
            .arg(format!("appauth/{}", *id))
            .query_async(&mut conn)
            .await?;

        if let Some(redis_token) = redis_token {
            if redis_token == token {
                return Ok(());
            }
        }

        let mut conn = self.pg_pool.acquire().await?;
        let record = database::find_appauth_by_id(&mut conn, id, self.table_name).await?;
        let real_token = record.token.expose_secret();
        if token != real_token {
            set_redis_token(&self.redis_pool, &record).await?;
            return Err(Error::InvalidToken);
        }
        Ok(())
    }
}

#[cfg(feature = "deadpool")]
#[async_trait]
impl super::AppAuthBackend for DeadpoolBackend {
    type Error = Error;

    async fn create_appauth(&self, app_auth: NewAppAuth) -> Result<AppAuth, Self::Error> {
        let mut conn = self.pg_pool.acquire().await?;
        let id = database::insert_app_auth(&mut conn, app_auth, self.table_name).await?;
        let appauth = database::find_appauth_by_id(&mut conn, id, self.table_name).await?;
        set_redis_token(&self.redis_pool, &appauth).await?;

        Ok(appauth)
    }

    async fn verify_token(&self, id: AppAuthId, token: &str) -> Result<(), Self::Error> {
        let mut conn = self.redis_pool.get().await?;

        let redis_token: Option<String> = redis::cmd("GET")
            .arg(format!("appauth/{}", *id))
            .query_async(&mut conn)
            .await?;

        if let Some(redis_token) = redis_token {
            if redis_token == token {
                return Ok(());
            }
        }

        let mut conn = self.pg_pool.acquire().await?;
        let record = database::find_appauth_by_id(&mut conn, id, self.table_name).await?;
        let real_token = record.token.expose_secret();
        if token != real_token {
            set_redis_token(&self.redis_pool, &record).await?;
            return Err(Error::InvalidToken);
        }
        Ok(())
    }
}

mod database {
    use secrecy::{ExposeSecret, Secret};
    use sqlx::{PgConnection, Row};

    use crate::appauth::{AppAuth, AppAuthId, NewAppAuth};

    pub async fn find_appauth_by_id(
        conn: &mut PgConnection,
        id: AppAuthId,
        table_name: &'static str,
    ) -> Result<AppAuth, sqlx::Error> {
        let r = sqlx::query(&format!(
            r#"
                SELECT * FROM {} WHERE id = $1
            "#,
            table_name
        ))
        .bind(*id)
        .fetch_one(conn)
        .await?;

        Ok(AppAuth {
            id: r.get(0),
            name: r.get(1),
            description: r.get(2),
            token: Secret::new(r.get(3)),
            meta: r.get(4),
            expires_at: r.get(5),
        })
    }

    pub async fn insert_app_auth(
        conn: &mut PgConnection,
        appauth: NewAppAuth,
        table_name: &'static str,
    ) -> Result<AppAuthId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(name, description, token, meta, expires_at) VALUES ($1, $2, $3, $4, $5)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(appauth.name)
        .bind(appauth.description)
        .bind(appauth.token.expose_secret())
        .bind(appauth.meta)
        .bind(appauth.expires_at)
        .fetch_one(conn)
        .await?;

        Ok(AppAuthId(rec.get(0)))
    }

    pub async fn insert_app_auth_with_id(
        conn: &mut PgConnection,
        id: AppAuthId,
        appauth: NewAppAuth,
        table_name: &'static str,
    ) -> Result<AppAuthId, sqlx::Error> {
        let rec = sqlx::query(&format!(
            r#"
                INSERT INTO {}(id, name, description, token, meta, expires_at) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id;
            "#,
            table_name
        ))
        .bind(*id)
        .bind(appauth.name)
        .bind(appauth.description)
        .bind(appauth.token.expose_secret())
        .bind(appauth.meta)
        .bind(appauth.expires_at)
        .fetch_one(conn)
        .await?;

        Ok(AppAuthId(rec.get(0)))
    }
}
