use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage,
};
use crate::auth::jwt::{Claims, validate_jwt};

pub async fn auth_middleware(
    req: ServiceRequest,
    next: actix_web::dev::Service<ServiceRequest>,
) -> Result<ServiceResponse, Error> {
    // Allow public endpoints to pass through (e.g. auth endpoints)
    let path = req.path().to_string();
    if path.starts_with("/auth/") || path == "/health" {
        return next.call(req).await;
    }

    // 1) Try Authorization: Bearer header
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

    // 2) Fallback: check HTTP-only cookie `access_token`
    if let Some(cookie) = req.cookie("access_token") {
        let token = cookie.value();
        if let Ok(claims) = validate_jwt(token) {
            req.extensions_mut().insert(claims);
            return next.call(req).await;
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Invalid or missing token"))
}

pub fn wrap() -> actix_web_lab::middleware::FromFn {
    from_fn(auth_middleware)
}