use actix_session::Session;
use actix_web::{post, HttpResponse, Responder};
use crate::auth::cookies::clear_access_token;
use serde_json::json;

#[post("/api/v1/auth/logout")]
pub async fn logout(session: Session) -> impl Responder {
    // Remove any server-side session state
    let _ = session.remove("jwt");

    // Instruct the browser to delete the auth cookie (Max-Age=0)
    HttpResponse::Ok()
        .cookie(clear_access_token())
        .json(json!({ "message": "Logged out" }))
}

