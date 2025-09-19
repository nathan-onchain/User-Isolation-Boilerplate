use actix_web::{web, App, HttpServer, middleware::Logger};
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_cors::Cors;
use std::env;

mod database;
mod auth;
mod models;
mod config;
mod services;
mod routes;

use database::db::establish_connection;
use config::cors;
use auth::middleware::wrap as auth_middleware;
use routes::auth_routes::public_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();
    
    // Initialize logging
    env_logger::init();

    // Get database URL from environment
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    // Create database connection pool
    let pool = establish_connection().await;

    // Get Redis URL for sessions (optional - you can use memory store for development)
    let redis_url = env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    // Create session store
    let store = RedisSessionStore::new(&redis_url)
        .await
        .expect("Failed to create Redis session store");

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
            .wrap(cors()) // Add CORS middleware
            .wrap(
                SessionMiddleware::builder(store.clone(), actix_web::cookie::Key::generate())
                    .cookie_secure(false) // Set to true in production with HTTPS
                    .build()
            )// Add session middleware
            .wrap(Logger::default()) // Add logging middleware
            .wrap(auth_middleware())// Add authentication middleware to all routes
            .service(public_routes())// Register public routes (auth endpoints, health check)
            
            // Add protected routes here
            // .service(protected_routes())
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}