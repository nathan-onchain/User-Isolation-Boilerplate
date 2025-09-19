use actix_web::{post, web, HttpResponse, Responder};
use sqlx::Pool;
use sqlx::Postgres;
use argon2::{Argon2, PasswordVerifier};
use argon2::password_hash::PasswordHash;
use crate::auth::jwt::create_jwt;
// Session removed - using JWT-only authentication
use crate::models::login::LoginPayload;
use crate::auth::cookies::set_access_token;



// Login handler
#[post("/login")]
pub async fn login(
    pool: web::Data<Pool<Postgres>>,
    payload: web::Json<LoginPayload>,
) -> impl Responder {
    let rec = match sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", payload.email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(result) => result,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let row = match rec {
        Some(r) => r,
        None => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    // verify password (argon2 PasswordHash)
    let parsed = match PasswordHash::new(&row.password_hash) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed).is_err() {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    // create JWT
    let token = match create_jwt(&row.id.to_string()) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

        // JWT-only authentication - no session cleanup needed

    // Send JWT as HTTP-only cookie
    HttpResponse::Ok()
        .cookie(set_access_token(&token))
        .json(serde_json::json!({"message": "Logged in successfully"}))
}