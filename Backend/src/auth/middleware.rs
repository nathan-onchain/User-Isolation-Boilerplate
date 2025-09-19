use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    Error, HttpMessage,
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use std::rc::Rc;

use crate::auth::jwt::validate_jwt;

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct AuthMiddlewareMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = Rc::clone(&self.service);

        Box::pin(async move {
            let path = req.path().to_string();

            // Allow public endpoints
            if path.starts_with("/api/v1/auth/") || path == "/health" {
                return srv.call(req).await;
            }

            // 1) Try Authorization: Bearer header
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(token) = auth_header.to_str() {
                    if token.starts_with("Bearer ") {
                        let token = token.trim_start_matches("Bearer ").trim();
                        if let Ok(claims) = validate_jwt(token) {
                            req.extensions_mut().insert(claims);
                            return srv.call(req).await;
                        }
                    }
                }
            }

            // 2) Fallback: HTTP-only cookie `access_token`
            if let Some(cookie) = req.cookie("access_token") {
                let token = cookie.value();
                if let Ok(claims) = validate_jwt(token) {
                    req.extensions_mut().insert(claims);
                    return srv.call(req).await;
                }
            }

            Err(ErrorUnauthorized("Invalid or missing token"))
        })
    }
}
