use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ResetRequest {
    pub email: String,
}


#[derive(Deserialize)]
pub struct ResetVerifyPayload {
    pub user_id: Uuid,
    pub email: String,
    pub otp: String,
    pub new_password: String,
    pub confirm_password: String,
}
