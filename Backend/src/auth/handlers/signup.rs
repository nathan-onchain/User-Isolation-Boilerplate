use actix_web::{post, web, HttpResponse, Responder};
use sqlx::Pool;
use sqlx::Postgres;
use crate::models::user::User;
use uuid::Uuid;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use crate::auth::jwt::create_jwt;
// Session removed - using JWT-only authentication
use crate::models::signup::RegisterPayload;
use crate::auth::cookies::set_access_token;




// Register handler
#[post("/register")]
pub async fn register(
    pool: web::Data<Pool<Postgres>>,
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

    let user = match created {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("register error: {}", e);
            // Check if it's a unique constraint violation (duplicate email)
            if e.to_string().contains("duplicate key value violates unique constraint") {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "Email already exists",
                    "message": "An account with this email address already exists"
                }));
            }
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Create JWT for the new user
    let token = match create_jwt(&user.id.to_string()) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

        // JWT-only authentication - no session cleanup needed

    // Send JWT as HTTP-only cookie
    HttpResponse::Created()
        .cookie(set_access_token(&token))
        .json(serde_json::json!({"message": "User registered successfully"}))
}
