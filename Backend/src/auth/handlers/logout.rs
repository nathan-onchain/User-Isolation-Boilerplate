// Session removed - using JWT-only authentication
use actix_web::{post, HttpResponse, Responder};
use crate::auth::cookies::clear_access_token;
use serde_json::json;

#[post("/logout")]
pub async fn logout() -> impl Responder {
    // JWT-only authentication - no session cleanup needed

    // Instruct the browser to delete the auth cookie (Max-Age=0)
    HttpResponse::Ok()
        .cookie(clear_access_token())
        .json(json!({ "message": "Logged out" }))
}

