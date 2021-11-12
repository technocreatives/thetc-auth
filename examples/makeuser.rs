use secrecy::ExposeSecret;
use sqlx::PgPool;
use thetc_auth::{password_strategy::{Argon2idStrategy, Strategy}, user::{NewUser, UserBackend}, username::ascii::AsciiUsername};

#[tokio::main]
async fn main() {
    let pool = PgPool::connect("postgres://thetcauth:thetcauth@localhost:61234/thetcauth")
        .await
        .unwrap();
    let strategy = Argon2idStrategy::new("delicious pepper".as_bytes().to_vec(), 15, 2, 1).unwrap();
    let users = thetc_auth::user::PgUsers::<_, AsciiUsername>::new(pool, "users", strategy.clone());

    let username = std::env::args().skip(1).next().unwrap();

    users
        .create_user(NewUser::new(&username, "password").unwrap())
        .await
        .unwrap();
    let user = users.find_user_by_username(&username).await.unwrap();
    println!("{:#?}", user);

    println!("{}", strategy.verify_password(user.password_hash.expose_secret(), "password").unwrap());
}
