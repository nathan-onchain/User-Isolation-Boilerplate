use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};

/// Hash a plaintext password with Argon2
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2.hash_password(password.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .map_err(|e| format!("Hashing error: {}", e))
}

/// Verify a plaintext password against a hash
pub fn verify_password(password: &str, hashed: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(hashed)
        .map_err(|e| format!("Invalid hash format: {}", e))?;
    
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
