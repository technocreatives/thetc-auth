use crate::password_strategy::Strategy;

struct UserManager<S: Strategy> {
    strategy: S,
}

pub mod postgres {
    use std::{convert::TryFrom, fmt::Display, hash::Hash};

    use secrecy::{ExposeSecret, Secret};
    use sqlx::PgPool;

    use crate::password_strategy::Strategy;

    #[nova::newtype(serde, sqlx, copy)]
    pub type UserId = uuid::Uuid;

    #[derive(Debug, thiserror::Error)]
    pub enum TryIntoUsernameError {
        #[error("Username must not be empty string.")]
        Empty,

        #[error("Non-printable characters found in username.")]
        NonPrintable,

        // It pains me to do this.
        #[error("Non-ASCII characters found in username.")]
        NonAscii,

        #[error("Username too long.")]
        UsernameTooLong,
    }

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize, sqlx::Type)]
    #[sqlx(transparent)]
    #[serde(try_from = "String")]
    pub struct Username(String);

    impl Username {
        fn into_inner(self) -> String {
            self.0
        }
    }

    impl Display for Username {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Display::fmt(&self.0, f)
        }
    }

    impl PartialEq for Username {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.0
                .to_ascii_lowercase()
                .eq(&other.0.to_ascii_lowercase())
        }
    }

    impl Eq for Username {}

    impl PartialOrd for Username {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.0
                .to_ascii_lowercase()
                .partial_cmp(&other.0.to_ascii_lowercase())
        }
    }

    impl Ord for Username {
        #[inline]
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0
                .to_ascii_lowercase()
                .cmp(&other.0.to_ascii_lowercase())
        }
    }

    impl Hash for Username {
        #[inline]
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.to_ascii_lowercase().hash(state)
        }
    }

    impl TryFrom<String> for Username {
        type Error = TryIntoUsernameError;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            let value = value.trim();

            if value.len() == 0 {
                return Err(TryIntoUsernameError::Empty);
            }

            if value.len() > 64 {
                return Err(TryIntoUsernameError::UsernameTooLong);
            }

            for c in value.chars() {
                if !c.is_ascii() {
                    return Err(TryIntoUsernameError::NonAscii);
                }

                if !c.is_ascii_graphic() {
                    return Err(TryIntoUsernameError::NonPrintable);
                }
            }

            Ok(Self(value.to_string()))
        }
    }

    #[derive(Debug)]
    pub struct NewUser {
        pub username: Username,
        pub password: Secret<String>,
        pub meta: serde_json::Value,
    }

    #[derive(Debug)]
    pub struct User {
        pub id: UserId,
        pub username: Username,
        pub password_hash: Secret<String>,
        pub meta: serde_json::Value,
    }

    #[derive(Debug, thiserror::Error)]
    enum Error {
        #[error("sqlx error")]
        Sqlx(#[from] sqlx::Error),

        #[error("password error")]
        Password(#[from] crate::password_strategy::Error),
    }

    struct Backend<S: Strategy> {
        strategy: S,
        pool: PgPool,
    }

    impl<S: Strategy> Backend<S>
    where
        Error: From<<S as Strategy>::Error>,
    {
        pub async fn create_user(&self, user: NewUser) -> Result<User, Error> {
            let password_hash = self
                .strategy
                .generate_password_hash(user.password.expose_secret())?;
            let mut conn = self.pool.acquire().await?;
            let user_id =
                database::insert_user(&mut conn, user.username, password_hash, user.meta).await?;
            Ok(database::find_user_by_id(&mut conn, user_id).await?)
        }
    }

    mod database {
        use secrecy::{ExposeSecret, Secret};
        use sqlx::PgConnection;

        use super::{User, UserId, Username};

        pub async fn insert_user(
            conn: &mut PgConnection,
            username: Username,
            password_hash: Secret<String>,
            meta: serde_json::Value,
        ) -> Result<UserId, sqlx::Error> {
            let rec = sqlx::query!(
                r#"
                    INSERT INTO users(username, password_hash, meta) VALUES ($1::text, $2, $3)
                    RETURNING id;
                "#,
                username.into_inner(),
                password_hash.expose_secret(),
                meta
            )
            .fetch_one(conn)
            .await?;

            Ok(UserId(rec.id))
        }

        pub async fn find_user_by_id(
            conn: &mut PgConnection,
            id: UserId,
        ) -> Result<User, sqlx::Error> {
            let r = sqlx::query!(
                r#"
                    SELECT
                        id as "id: UserId",
                        username as "username: Username",
                        password_hash,
                        meta
                    FROM users
                    WHERE id = $1
                    LIMIT 1;
                "#,
                *id
            )
            .fetch_one(conn)
            .await?;

            Ok(User {
                id: r.id,
                username: r.username,
                password_hash: Secret::new(r.password_hash),
                meta: r.meta,
            })
        }
    }
}
