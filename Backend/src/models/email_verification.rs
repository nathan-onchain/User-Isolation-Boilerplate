use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailVerification {
    pub id: Uuid,
    pub email: String,
    pub otp_code: String,
    pub created_at: DateTime<Utc>,
    pub verified: bool,
    pub attempt_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailPayload {
    pub email: String,
    pub otp: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendOtpPayload {
    pub email: String,
}
