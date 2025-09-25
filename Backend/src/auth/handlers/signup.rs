use actix_web::{post, web, HttpResponse, Responder};
use sqlx::Pool;
use sqlx::Postgres;
use uuid::Uuid;


use crate::auth::jwt::create_jwt;
use crate::auth::validation::validate_register_payload;
use crate::models::signup::RegisterPayload;
use crate::models::user::User;
use crate::auth::cookies::set_access_token;
use crate::utils::hash::{hash_password};




// Register handler
#[post("/register")]
pub async fn register(
    pool: web::Data<Pool<Postgres>>,
    payload: web::Json<RegisterPayload>,
) -> impl Responder {
    // Comprehensive input validation
    match validate_register_payload(&payload.username, &payload.email, &payload.password) {
        Ok(_) => {},
        Err(validation_errors) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Validation failed",
                "details": validation_errors
            }));
        }
    }

    // hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing error: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
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
