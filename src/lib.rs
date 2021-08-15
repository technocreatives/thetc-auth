pub mod password_strategy;
pub mod session;

mod database {
    use secrecy::Secret;

    pub struct User {
        username: String,
        password_hash: Secret<String>,
        meta: serde_json::Value,
    }

    pub struct NewUser {
        username: String,
        password: Secret<String>,
        meta: serde_json::Value,
    }
}
