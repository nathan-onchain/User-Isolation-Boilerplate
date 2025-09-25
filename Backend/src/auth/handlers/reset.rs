use actix_web::error::ErrorInternalServerError;
use actix_web::{HttpResponse, Responder, post, web};
use chrono::{Duration, Utc};
use sqlx::Pool;
use sqlx::Postgres;


use crate::models::reset::{ResetRequest, ResetVerifyPayload};
use crate::utils::hash::hash_password;
use crate::utils::otp::{generate_otp, send_otp_email};

#[post("/reset/request")]
pub async fn reset_request(pool: web::Data<Pool<Postgres>>, data: web::Json<ResetRequest>) -> impl Responder {
    let email = data.email.to_lowercase();

    // 1. Check if user exists (but do not reveal result!)
    let user = sqlx::query!("SELECT id FROM users WHERE email = $1", email)
        .fetch_optional(pool.get_ref())
        .await;

    match user {
        Ok(Some(record)) => {
            let user_id = record.id;

            // 2. Generate OTP
            let otp = generate_otp();
            let expires_at = Utc::now() + Duration::minutes(10);

            // 3. Store OTP in password_resets table
            let query = r#"
                INSERT INTO password_resets (user_id, otp_code, expires_at, used)
                VALUES ($1, $2, $3, FALSE)
                ON CONFLICT (user_id) DO UPDATE
                SET otp_code = $2, expires_at = $3, used = FALSE
            "#;

            if let Err(e) = sqlx::query(query)
                .bind(user_id)
                .bind(&otp)
                .bind(expires_at)
                .execute(pool.get_ref())
                .await
            {
                eprintln!("DB error inserting password reset: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }

            // 4. Sent OTP email
            if let Err(e) = send_otp_email(&email, &otp) {
                eprintln!("Error Sending OTP email: {:?}", e);
            }
        }

        Ok(None) => {
            // Do nothing if user does not exist
        }

        Err(e) => {
            eprintln!("DB query error: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    }

    // 5. Always return a Neutral response
    HttpResponse::Ok().json(serde_json::json!({
        "message": "If this email is registered, a reset code has been sent."
    }))
}

// Password and OTP verification function
#[post("/auth/reset/verify")]
pub async fn reset_verify(
    pool: web::Data<Pool<Postgres>>,
    payload: web::Json<ResetVerifyPayload>,
) -> Result<impl Responder, actix_web::Error> {
    // 1. confirm password check
    if payload.new_password != payload.confirm_password {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Passwords do not match"
        })));
    }

    // 2. check OTP validity
    let otp_row = sqlx::query!(
        "SELECT id, expires_at, used FROM password_resets WHERE user_id = $1 AND otp_code = $2",
        payload.user_id,
        payload.otp
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ErrorInternalServerError(e))?;
    

    let otp = match otp_row {
        Some(row) => row,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid or expired OTP"
            })));
        }
    };

    if otp.used || otp.expires_at < chrono::Utc::now() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "OTP expired or already used"
        })));
    }

    // 3. hash new password with helper
    let hashed = hash_password(&payload.new_password)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to hash password"))?;

    // 4. update users table
    let result = sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE email = $2",
        hashed,
        payload.email
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("DB update failed"))?;
    
    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().body("No user found"));
    }
    

    // 5. mark OTP as used
    sqlx::query!(
        "UPDATE password_resets SET used = TRUE WHERE id = $1",
        otp.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|e| ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Password reset successful"
    })))
}
