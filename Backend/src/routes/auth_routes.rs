use actix_web::{web, Scope};
use crate::auth::handlers::{login, logout, signup};

/// Auth routes configuration
/// This module provides route grouping for authentication endpoints
pub fn auth_routes() -> Scope {
    web::scope("/api/v1/auth")
        .service(login::login)
        .service(signup::register)
        .service(logout::logout)
}

/// Public routes that don't require authentication
pub fn public_routes() -> Scope {
    web::scope("")
        .service(auth_routes())
        .route("/health", web::get().to(|| async { "Server is healthy" }))
}

