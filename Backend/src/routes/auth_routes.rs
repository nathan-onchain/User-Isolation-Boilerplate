use actix_web::{web, Scope};
use crate::auth::handlers::{login, logout, signup, reset};

/// Auth routes configuration
/// This module provides route grouping for authentication endpoints
pub fn auth_routes() -> Scope {
    web::scope("/api/v1/auth")
        .service(login::login)
        .service(signup::register)
        .service(logout::logout)
        .service(reset::reset_request)
        .service(reset::reset_verify)
}

/// Public routes that don't require authentication
pub fn public_routes() -> Scope {
    web::scope("")
        .service(auth_routes())
        .route("/health", web::get().to(|| async { "Server is healthy" }))
}

