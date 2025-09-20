// Cross Origin Resource Sharing Configuration
use actix_cors::Cors;
use actix_web::http::header;
use std::env;

pub mod security;

pub fn cors() -> Cors {
    // Environment-driven CORS: allow all in non-production; restrict in production via CORS_ALLOWED_ORIGINS
    let environment = env::var("RUST_ENV").ok().unwrap_or_else(|| "development".to_string());
    let allowed_origins_env = env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
    let allowed_origins: Vec<String> = allowed_origins_env
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if environment != "production" || allowed_origins.is_empty() {
        // Development or no explicit origins: permissive with credentials
        return Cors::default()
            .allow_any_origin()
            .allowed_methods(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) 
            .allowed_headers([header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE])
            .expose_any_header()
            .supports_credentials()
            .max_age(3600);
    }

    // Production with explicit origins: restrict to the list and allow credentials
    let mut cors = Cors::default()
        .allowed_methods(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) 
        .allowed_headers([header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE])
        .expose_any_header()
        .supports_credentials()
        .max_age(3600);

    for origin in allowed_origins {
        cors = cors.allowed_origin(&origin);
    }

    cors
}