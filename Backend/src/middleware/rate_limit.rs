use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use std::rc::Rc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;

// Simple in-memory rate limiter (for production, use Redis or similar)
type RateLimitStore = Mutex<HashMap<String, (Instant, u32)>>;

static RATE_LIMIT_STORE: Lazy<RateLimitStore> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

pub struct RateLimitMiddleware {
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            max_requests,
            window_duration,
        }
    }

    pub fn auth_endpoints() -> Self {
        // Stricter rate limiting for auth endpoints
        Self::new(5, Duration::from_secs(300)) // 5 requests per 5 minutes
    }

    pub fn general() -> Self {
        // General rate limiting
        Self::new(100, Duration::from_secs(60)) // 100 requests per minute
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddlewareService {
            service: Rc::new(service),
            max_requests: self.max_requests,
            window_duration: self.window_duration,
        })
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: Rc<S>,
    max_requests: u32,
    window_duration: Duration,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
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
        let max_requests = self.max_requests;
        let window_duration = self.window_duration;

        Box::pin(async move {
            // Get client IP for rate limiting
            let client_ip = req
                .connection_info()
                .peer_addr()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            // Check rate limit
            if let Ok(mut store) = RATE_LIMIT_STORE.lock() {
                let now = Instant::now();
                
                // Get current state
                let current_state = store.get(&client_ip).cloned();
                
                match current_state {
                    Some((window_start, request_count)) => {
                        if now.duration_since(window_start) < window_duration {
                            if request_count >= max_requests {
                                tracing::warn!("Rate limit exceeded for IP: {}", client_ip);
                                return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"));
                            }
                            // Increment counter
                            store.insert(client_ip.clone(), (window_start, request_count + 1));
                        } else {
                            // Reset window
                            store.insert(client_ip.clone(), (now, 1));
                        }
                    }
                    None => {
                        // First request
                        store.insert(client_ip.clone(), (now, 1));
                    }
                }
            }

            srv.call(req).await
        })
    }
}
