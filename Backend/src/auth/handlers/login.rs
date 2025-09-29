use actix_web::{post, web, HttpResponse, Responder};
use sqlx::Pool;
use sqlx::Postgres;
use sqlx::types::chrono::Utc;



use crate::auth::jwt::create_jwt;
use crate::auth::validation::validate_login_payload;
use crate::models::login::LoginPayload;
use crate::auth::cookies::set_access_token;
use crate::utils::hash::verify_password;
use crate::config::login::LoginLimitConfig;



// Login handler
#[post("/login")]
pub async fn login(
    pool: web::Data<Pool<Postgres>>,
    config: web::Data<LoginLimitConfig>,
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

    // 3. Check failed attempts in lockout window
    let recent_attempts = match sqlx::query!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM failed_logins
        WHERE user_id = $1
        AND attempt_time > NOW() - ($2::int * interval '1 second')
        "#,
        row.id,
        config.lockout_secs as i32
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(r) => r.count,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if recent_attempts >= config.max_attempts as i64 {
        return HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Too many failed login attempts. Please try again later."
        }))
    }



    // verify password (argon2 PasswordHash)
    match verify_password(&payload.password, &row.password_hash) {
        Ok(true) => {
            // ✅ Success → clear failed attempts
            let _ = sqlx::query!("DELETE FROM failed_logins WHERE user_id = $1", row.id)
                .execute(pool.get_ref())
                .await;

            // Create JWT
            let token = match create_jwt(&row.id.to_string()) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().finish(),
            };

            return HttpResponse::Ok()
                .cookie(set_access_token(&token))
                .json(serde_json::json!({"message": "Logged in successfully"}))

        } // Password correct - Continue

        Ok(false) => {
            // Wrong password - log attempt
            let _ = sqlx::query!(
                "INSERT INTO failed_logins (user_id, attempt_time) VALUES ($1, $2)",
                row.id,
                Utc::now()
            )
            .execute(pool.get_ref())
            .await;

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
}