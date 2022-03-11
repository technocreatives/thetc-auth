use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use async_trait::async_trait;
use deadpool::managed::{Manager, PoolError, RecycleResult};
use sqlx::postgres::PgConnectOptions;
use sqlx::{PgConnection, Error as SqlxError, ConnectOptions, Connection};

type Pool = deadpool::managed::Pool<PgHandle>;

#[derive(Clone)]
pub struct PgPool(Pool);

impl PgPool {
    pub async fn acquire(&self) -> Result<deadpool::managed::Object<PgHandle>, PoolError<SqlxError>> {
        self.0.get().await
    }
}

impl Deref for PgPool {
    type Target = Pool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PgPool {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Debug for PgPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPool").finish()
    }
}

pub struct PgHandle {
    url: String,
}

impl PgPool {
    pub fn new(url: String, size: usize) -> PgPool {
        let manager = PgHandle { url };
        PgPool(Pool::builder(manager).max_size(size).build().unwrap())
    }
}

#[async_trait]
impl Manager for PgHandle {
    type Type = PgConnection;
    type Error = SqlxError;
    
    async fn create(&self) -> Result<PgConnection, SqlxError> {
        PgConnectOptions::from_str(&self.url)?
            .connect()
            .await
    }
    async fn recycle(&self, obj: &mut PgConnection) -> RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}
