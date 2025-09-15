use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::PgPool;
use crate::models::user::User;
use uuid::Uuid;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};
use crate::auth::jwt::create_jwt;

// Register Data
#[derive(Deserialize)]
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: String,
}

// Login Data
#[derive(Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
}


// Register handler
#[post("/api/v1/auth/register")]
pub async fn register(
    pool: web::Data<PgPool>,
    payload: web::Json<RegisterPayload>,
) -> impl Responder {
    // basic validation
    if payload.password.len() < 8 {
        return HttpResponse::BadRequest().body("password too short");
    }

    // hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(payload.password.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .map_err(|_| HttpResponse::InternalServerError().finish());

    let password_hash = match password_hash {
        Ok(h) => h,
        Err(e) => return e,
    };

    // insert user and return full record
    let created = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, username, email, password_hash, created_at)
        VALUES ($1, $2, $3, $4, NOW())
        RETURNING id, username, email, password_hash, created_at
        "#,
        Uuid::new_v4(),
        payload.username,
        payload.email,
        password_hash
    )
    .fetch_one(pool.get_ref())
    .await;

    match created {
        Ok(user) => HttpResponse::Created().json(user),
        Err(e) => {
            tracing::error!("register error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}



// Login handler
#[post("/api/v1/auth/login")]
pub async fn login(
    pool: web::Data<PgPool>,
    payload: web::Json<LoginPayload>,
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

    HttpResponse::Ok().json(serde_json::json!({"access_token": token}))
}