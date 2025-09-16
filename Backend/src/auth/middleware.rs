use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage,
};
use crate::auth::jwt::Claims;

pub async fn auth_middleware(
    req: ServiceRequest,
    next: actix_web::dev::Service<ServiceRequest>,
) -> Result<ServiceResponse, Error> {
    // Allow public endpoints to pass through (e.g. /health, /auth/*)
    let path = req.path().to_string();
    if path.starts_with("/auth/") || path == "/health" {
        return next.call(req).await;
    }

    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(token) = auth_header.to_str() {
            if token.starts_with("Bearer ") {
                let token = token.trim_start_matches("Bearer ").trim();
                match validate_jwt(token) {
                    Ok(claims) => {
                        req.extensions_mut().insert(claims);
                        return next.call(req).await;
                    }
                    Err(_) => {}
                }
            }
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Invalid or missing token"))
}

pub fn wrap() -> actix_web_lab::middleware::FromFn {
    from_fn(auth_middleware)
}