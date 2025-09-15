use sqlx::{PgPool, PgPoolOptions};
use std::env;
use std::time::Duration;

// Creates a connection to the database
fn establish_connection() -> PgPool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    PgPoolOptions::new()
        .max_connections(5)
        .connect_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .expect("Failed to connect to database");
}