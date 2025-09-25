use actix_web::{post, web, HttpResponse, Responder};
use sqlx::Pool;
use sqlx::Postgres;



use crate::auth::jwt::create_jwt;
use crate::auth::validation::validate_login_payload;
use crate::models::login::LoginPayload;
use crate::auth::cookies::set_access_token;
use crate::utils::hash::verify_password;



// Login handler
#[post("/login")]
pub async fn login(
    pool: web::Data<Pool<Postgres>>,
    payload: web::Json<LoginPayload>,
) -> impl Responder {
    // Input validation
    match validate_login_payload(&payload.email, &payload.password) {
        Ok(_) => {},
        Err(validation_errors) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Validation failed",
                "details": validation_errors
            }));
        }
    }

    let rec = match sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", payload.email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(result) => result,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let row = match rec {
        Some(r) => r,
        None => {
            // Log failed login attempt for security monitoring
            tracing::warn!("Failed login attempt for email: {}", payload.email);
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            }));
        }
    };

    // verify password (argon2 PasswordHash)
    match verify_password(&payload.password, &row.password_hash) {
        Ok(true) => {} // Password correct - Continue
        Ok(false) => {
            tracing::warn!("Failed login attempt for email: {}", payload.email);
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            }));
        }
        Err(e) => {
            tracing::error!("Password verification error: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    }


    // create JWT
    let token = match create_jwt(&row.id.to_string()) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };


    // Send JWT as HTTP-only cookie
    HttpResponse::Ok()
        .cookie(set_access_token(&token))
        .json(serde_json::json!({"message": "Logged in successfully"}))
}