use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

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

    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("Invalid email regex");
    
    if !email_regex.is_match(email) {
        return Err(ValidationError {
            field: "email".to_string(),
            message: "Invalid email format".to_string(),
        });
    }

    Ok(())
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

    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one uppercase letter".to_string(),
        });
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one lowercase letter".to_string(),
        });
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must contain at least one number".to_string(),
        });
    }

    let special_chars = Regex::new(r"[!@#$%^&*()_+\-=\[\]{};':\|,.<>/?]")
        .expect("Invalid special chars regex");
    
    if !special_chars.is_match(password) {
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

    let username_regex = Regex::new(r"^[a-zA-Z0-9_]+$")
        .expect("Invalid username regex");
    
    if !username_regex.is_match(username) {
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

    if let Err(e) = validate_username(&username) {
        errors.push(e);
    }

    if let Err(e) = validate_email(&email) {
        errors.push(e);
    }

    if let Err(e) = validate_password(&password) {
        errors.push(e);
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

    if let Err(e) = validate_email(&email) {
        errors.push(e);
    }

    if password.is_empty() {
        errors.push(ValidationError {
            field: "password".to_string(),
            message: "Password is required".to_string(),
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
