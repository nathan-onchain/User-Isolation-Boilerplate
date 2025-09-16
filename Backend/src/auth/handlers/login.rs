use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use crate::models::user::User;
use uuid::Uuid;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};
use crate::auth::jwt::create_jwt;
use actix_session::Session;
use crate::models::login::LoginPayload;
use crate::auth::cookies::set_access_token;



// Login handler
#[post("/api/v1/auth/login")]
pub async fn login(
    pool: web::Data<PgPool>,
    payload: web::Json<LoginPayload>,
    session: Session,
) -> impl Responder {
    let rec = sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", payload.email)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|_| HttpResponse::InternalServerError().finish())?;

    let row = match rec {
        Some(r) => r,
        None => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    // verify password (argon2 PasswordHash)
    let parsed = PasswordHash::new(&row.password_hash).map_err(|_| HttpResponse::InternalServerError().finish())?;
    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed).is_err() {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    // create JWT
    let token = create_jwt(&row.id.to_string()).map_err(|_| HttpResponse::InternalServerError().finish())?;

    // Optional: clear any previous server-side session token
    let _ = session.remove("jwt");

    // Send JWT as HTTP-only cookie
    HttpResponse::Ok()
        .cookie(set_access_token(&token))
        .json(serde_json::json!({"message": "Logged in successfully"}))
}