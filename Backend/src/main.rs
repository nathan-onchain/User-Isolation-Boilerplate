use actix_web::{web, App, HttpServer, middleware::Logger};
// Session middleware removed - using JWT-only authentication
use std::env;

mod database;
mod auth;
mod models;
mod config;
mod services;
mod routes;
mod middleware;

use database::db::establish_connection;
use config::cors;
use auth::middleware::AuthMiddleware;
use middleware::security::SecurityHeadersMiddleware;
use routes::auth_routes::public_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();
    
    // Initialize logging
    env_logger::init();

    // Create database connection pool
    let pool = establish_connection().await;

    // Session management removed - using JWT-only authentication

    // Get server configuration
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");

    println!("🚀 Starting server on {}:{}", host, port);

    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            // Add database pool to app data
            .app_data(web::Data::new(pool.clone()))
            .wrap(SecurityHeadersMiddleware) // Add security headers
            .wrap(cors()) // Add CORS middleware
            .wrap(AuthMiddleware)// Add authentication middleware to all routes
            .wrap(Logger::default()) // Add logging middleware
            .service(public_routes())// Register public routes (auth endpoints, health check)
            
            // Add protected routes here
            // .service(protected_routes())
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}