use std::env;
use std::time::Duration;

pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiration_hours: u64,
    pub password_min_length: usize,
    pub password_max_length: usize,
    pub rate_limit_auth_requests: u32,
    pub rate_limit_auth_window_minutes: u64,
    pub rate_limit_general_requests: u32,
    pub rate_limit_general_window_minutes: u64,
    pub enable_security_headers: bool,
    pub enable_rate_limiting: bool,
    pub log_security_events: bool,
}

impl SecurityConfig {
    pub fn from_env() -> Self {
        Self {
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .expect("JWT_EXPIRATION_HOURS must be a number"),
            password_min_length: env::var("PASSWORD_MIN_LENGTH")
                .unwrap_or_else(|_| "8".to_string())
                .parse()
                .expect("PASSWORD_MIN_LENGTH must be a number"),
            password_max_length: env::var("PASSWORD_MAX_LENGTH")
                .unwrap_or_else(|_| "128".to_string())
                .parse()
                .expect("PASSWORD_MAX_LENGTH must be a number"),
            rate_limit_auth_requests: env::var("RATE_LIMIT_AUTH_REQUESTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("RATE_LIMIT_AUTH_REQUESTS must be a number"),
            rate_limit_auth_window_minutes: env::var("RATE_LIMIT_AUTH_WINDOW_MINUTES")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("RATE_LIMIT_AUTH_WINDOW_MINUTES must be a number"),
            rate_limit_general_requests: env::var("RATE_LIMIT_GENERAL_REQUESTS")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .expect("RATE_LIMIT_GENERAL_REQUESTS must be a number"),
            rate_limit_general_window_minutes: env::var("RATE_LIMIT_GENERAL_WINDOW_MINUTES")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .expect("RATE_LIMIT_GENERAL_WINDOW_MINUTES must be a number"),
            enable_security_headers: env::var("ENABLE_SECURITY_HEADERS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_rate_limiting: env::var("ENABLE_RATE_LIMITING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            log_security_events: env::var("LOG_SECURITY_EVENTS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        }
    }

    pub fn is_production(&self) -> bool {
        env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()) == "production"
    }

    pub fn get_auth_rate_limit_window(&self) -> Duration {
        Duration::from_secs(self.rate_limit_auth_window_minutes * 60)
    }

    pub fn get_general_rate_limit_window(&self) -> Duration {
        Duration::from_secs(self.rate_limit_general_window_minutes * 60)
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "default-secret-change-in-production".to_string(),
            jwt_expiration_hours: 24,
            password_min_length: 8,
            password_max_length: 128,
            rate_limit_auth_requests: 5,
            rate_limit_auth_window_minutes: 5,
            rate_limit_general_requests: 100,
            rate_limit_general_window_minutes: 1,
            enable_security_headers: true,
            enable_rate_limiting: true,
            log_security_events: true,
        }
    }
}
