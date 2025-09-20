use validator::validate_email as is_valid_email;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{warn, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

// Precompiled regexes for better performance
static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_]+$").expect("Invalid username regex")
});

static SPECIAL_CHARS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[!@#$%^&*()_+\-=\[\]{};':\|,.<>/?]").expect("Invalid special chars regex")
});

// Common weak passwords to check against
static COMMON_PASSWORDS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "12345678", "password", "123456789", "1234567890", "qwerty123",
        "password123", "admin123", "letmein", "welcome123", "monkey123",
        "dragon123", "master123", "hello123", "login123", "princess123",
        "qwertyuiop", "123456789a", "password1", "1234567890a", "admin1234"
    ]
});

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError {
            field: "email".to_string(),
            message: "Email is required".to_string(),
        });
    }

    if email.len() > 254 {
        return Err(ValidationError {
            field: "email".to_string(),
            message: "Email is too long".to_string(),
        });
    }

    // Use validator crate for email validation
    if is_valid_email(email) {
        Ok(())
    } else {
        warn!("Invalid email format attempted: {}", email);
        Err(ValidationError {
            field: "email".to_string(),
            message: "Invalid email format".to_string(),
        })
    }
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password is required".to_string(),
        });
    }

    if password.len() < 8 {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must be at least 8 characters long".to_string(),
        });
    }

    if password.len() > 128 {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password is too long".to_string(),
        });
    }

    // Check for spaces in password
    if password.contains(' ') {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password cannot contain spaces".to_string(),
        });
    }

    // Check against common weak passwords
    if COMMON_PASSWORDS.contains(&password.to_lowercase().as_str()) {
        warn!("Common password attempted: {}", password);
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password is too common, please choose a stronger password".to_string(),
        });
    }

    // Check for at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one uppercase letter".to_string(),
        });
    }

    // Check for at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one lowercase letter".to_string(),
        });
    }

    // Check for at least one digit
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one number".to_string(),
        });
    }

    // Check for at least one special character
    if !SPECIAL_CHARS_REGEX.is_match(password) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one special character".to_string(),
        });
    }

    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username is required".to_string(),
        });
    }

    if username.len() < 3 {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username must be at least 3 characters long".to_string(),
        });
    }

    if username.len() > 50 {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username is too long".to_string(),
        });
    }

    if !USERNAME_REGEX.is_match(username) {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username can only contain letters, numbers, and underscores".to_string(),
        });
    }

    Ok(())
}

pub fn sanitize_input(input: &str) -> String {
    input.trim().to_string()
}

pub fn validate_register_payload(
    username: &str,
    email: &str,
    password: &str,
) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    let username = sanitize_input(username);
    let email = sanitize_input(email);
    let password = sanitize_input(password);

    // Validate each field
    if let Err(e) = validate_username(&username) {
        errors.push(e);
    }

    if let Err(e) = validate_email(&email) {
        errors.push(e);
    }

    if let Err(e) = validate_password(&password) {
        errors.push(e);
    }

    // Log validation failures for analytics
    if !errors.is_empty() {
        warn!("Registration validation failed for email: {}, errors: {}", 
                email, errors.len());
    } else {
        info!("Registration validation passed for email: {}", email);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_login_payload(email: &str, password: &str) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    let email = sanitize_input(email);
    let password = sanitize_input(password);

    // For login, we only validate email format and password presence
    // We don't validate password strength to avoid enumeration attacks
    if let Err(e) = validate_email(&email) {
        errors.push(e);
    }

    if password.is_empty() {
        errors.push(ValidationError {
            field: "password".to_string(),
            message: "Password is required".to_string(),
        });
    }

    // Log validation failures (but don't expose specific details)
    if !errors.is_empty() {
        warn!("Login validation failed for email: {}", email);
    } else {
        info!("Login validation passed for email: {}", email);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// Additional validation for password reset and other sensitive operations
pub fn validate_password_reset_payload(email: &str) -> Result<(), ValidationError> {
    let email = sanitize_input(email);
    
    match validate_email(&email) {
        Ok(_) => {
            info!("Password reset validation passed for email: {}", email);
            Ok(())
        },
        Err(e) => {
            warn!("Password reset validation failed for email: {}", email);
            Err(e)
        }
    }
}

// Validate password strength for password change operations
pub fn validate_password_change_payload(
    current_password: &str,
    new_password: &str,
) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    let current_password = sanitize_input(current_password);
    let new_password = sanitize_input(new_password);

    if current_password.is_empty() {
        errors.push(ValidationError {
            field: "current_password".to_string(),
            message: "Current password is required".to_string(),
        });
    }

    if let Err(e) = validate_password(&new_password) {
        errors.push(e);
    }

    // Check if new password is different from current
    if current_password == new_password {
        errors.push(ValidationError {
            field: "new_password".to_string(),
            message: "New password must be different from current password".to_string(),
        });
    }

    if !errors.is_empty() {
        warn!("Password change validation failed");
    } else {
        info!("Password change validation passed");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}