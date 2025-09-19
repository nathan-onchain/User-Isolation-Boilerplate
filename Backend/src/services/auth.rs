use actix_web::{web, Scope};
use crate::auth::handlers::{login, logout, signup};

/// Auth service configuration
/// Groups all authentication-related endpoints under /api/v1/auth
pub fn auth_service() -> Scope {
    web::scope("/api/v1/auth")
        .service(login::login)
        .service(signup::register)
        .service(logout::logout)
}

/// Health check endpoint for auth service
pub fn health_service() -> Scope {
    web::scope("/health")
        .route("", web::get().to(|| async { "Auth service is healthy" }))
}

