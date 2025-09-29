#[derive(Debug, Clone)]
pub struct LoginLimitConfig {
    pub max_attempts: i32,
    pub lockout_secs: i64,
}

impl LoginLimitConfig {
    pub fn from_env() -> Self {
        Self {
            max_attempts: std::env::var("LOGIN_MAX_ATTEMPTS")
                .unwrap_or_else(|_| "5".into())
                .parse()
                .unwrap_or(5),
            lockout_secs: std::env::var("LOGIN_LOCKOUT_SECS")
                .unwrap_or_else(|_| "300".into())
                .parse()
                .unwrap_or(300),
        }
    }
}
