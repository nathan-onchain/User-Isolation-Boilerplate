use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, http::header::{HeaderName, HeaderValue},
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use std::rc::Rc;

pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct SecurityHeadersMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
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
            let mut res = srv.call(req).await?;
            
            // Add security headers
            let headers = res.headers_mut();
            
            // Prevent clickjacking
            if let (Ok(name), Ok(value)) = ("X-Frame-Options".parse::<HeaderName>(), "DENY".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            // Prevent MIME type sniffing
            if let (Ok(name), Ok(value)) = ("X-Content-Type-Options".parse::<HeaderName>(), "nosniff".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            // Enable XSS protection
            if let (Ok(name), Ok(value)) = ("X-XSS-Protection".parse::<HeaderName>(), "1; mode=block".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            // Strict Transport Security (only in production)
            if cfg!(not(debug_assertions)) {
                if let (Ok(name), Ok(value)) = ("Strict-Transport-Security".parse::<HeaderName>(), "max-age=31536000; includeSubDomains".parse::<HeaderValue>()) {
                    headers.insert(name, value);
                }
            }
            
            // Content Security Policy
            if let (Ok(name), Ok(value)) = ("Content-Security-Policy".parse::<HeaderName>(), "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            // Referrer Policy
            if let (Ok(name), Ok(value)) = ("Referrer-Policy".parse::<HeaderName>(), "strict-origin-when-cross-origin".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            // Permissions Policy
            if let (Ok(name), Ok(value)) = ("Permissions-Policy".parse::<HeaderName>(), "geolocation=(), microphone=(), camera=()".parse::<HeaderValue>()) {
                headers.insert(name, value);
            }
            
            Ok(res)
        })
    }
}
