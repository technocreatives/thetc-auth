use std::convert::TryFrom;

use argon2::{
    password_hash::{Salt, SaltString},
    Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier,
};
use secrecy::Secret;

pub trait Strategy: Send + Sync {
    fn generate_password_hash(&self, input: &str) -> Result<Secret<String>, Error>;
    fn verify_password(&self, hash: &str, input: &str) -> Result<bool, Error>;
}

#[derive(Debug, Clone)]
pub struct Argon2idStrategy {
    /// Goes with a salt. A shared salt that is mixed into all password hashing to ensure that if
    /// the database is leaked, without this extra piece, brute forcing is going to be
    /// effectively impossible.
    ///
    /// TODO: fix this with Secret.
    pepper: Vec<u8>,

    /// Memory to use in megabytes. Minimum is 15MB.
    memory_mib: u32,

    /// Iteration count. Minimum is 2.
    iteration_count: u32,

    /// Parallelism level. Minimum is 1.
    parallelism_degree: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Provided pepper is too weak. Minimum size: 8")]
    PepperTooWeak,

    #[error("Memory use is too weak. Minimum size: 15 MiB")]
    MemoryUseTooWeak,

    #[error("Too few iterations. Minimum: 2")]
    IterationTooWeak,

    #[error("Parallelism must be at least 1.")]
    ParallelismTooWeak,

    #[error("Password must be at least 8 characters.")]
    PasswordTooShort,

    #[error("A strategy function has been misused")]
    Strategy(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl Argon2idStrategy {
    pub fn new(
        pepper: Vec<u8>,
        memory_mib: u32,
        iteration_count: u32,
        parallelism_degree: u32,
    ) -> Result<Self, Error> {
        if pepper.len() < 8 {
            return Err(Error::PepperTooWeak);
        }

        if memory_mib < 15 {
            return Err(Error::MemoryUseTooWeak);
        }

        if iteration_count < 2 {
            return Err(Error::IterationTooWeak);
        }

        if parallelism_degree < 1 {
            return Err(Error::ParallelismTooWeak);
        }

        Ok(Self {
            pepper,
            memory_mib,
            iteration_count,
            parallelism_degree,
        })
    }
}

impl Argon2idStrategy {
    fn argon2_instance(&self) -> Argon2<'_> {
        Argon2::new_with_secret(
            &self.pepper,
            Default::default(),
            Default::default(),
            Params::new(
                self.memory_mib * 1024,
                self.iteration_count,
                self.parallelism_degree,
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }
}

pub mod argon2id {
    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("Error handling argon2id hashing.")]
        Argon2PasswordHash(#[from] argon2::password_hash::Error),
    }
}

impl Strategy for Argon2idStrategy {
    fn generate_password_hash(&self, input: &str) -> Result<Secret<String>, Error> {
        if input.len() < 8 {
            return Err(Error::PasswordTooShort);
        }

        let argon2 = self.argon2_instance();
        let salt = SaltString::generate(&mut rand::thread_rng());

        let result = argon2
            .hash_password(input.as_bytes(), &Salt::try_from(salt.as_ref()).unwrap())
            .map_err(|e| Error::Strategy(Box::new(e)))?
            .to_string();

        Ok(Secret::new(result))
    }

    fn verify_password(&self, hash: &str, input: &str) -> Result<bool, Error> {
        let argon2 = self.argon2_instance();

        let hash = PasswordHash::new(hash).map_err(|e| Error::Strategy(Box::new(e)))?;
        match argon2.verify_password(input.as_bytes(), &hash) {
            Ok(_) => Ok(true),
            Err(e) => match e {
                argon2::password_hash::Error::Password => Ok(false),
                _ => Err(Error::Strategy(Box::new(e))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{Argon2idStrategy, Strategy};

    #[test]
    fn generate_password() {
        let strat = Argon2idStrategy::new("hello pepper is my friend".into(), 15, 4, 1).unwrap();
        let result = strat.generate_password_hash("this is my password").unwrap();
        println!("{}", result.expose_secret());

        assert!(strat
            .verify_password(result.expose_secret(), "this is my password")
            .unwrap());
        assert!(!strat
            .verify_password(result.expose_secret(), "this is not my password")
            .unwrap());
    }
}
