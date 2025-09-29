use chrono::{DateTime, Duration, Utc};
use std::env;

#[derive(Debug, Clone)]
pub struct OtpConfig {
    pub limit_per_hour: i64,
    pub min_interval_secs: i64,
    pub expiry_minutes: i64,
}

impl OtpConfig {
    pub fn from_env() -> Self {
        Self {
            limit_per_hour: env::var("OTP_LIMIT_PER_HOUR")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("OTP_LIMIT_PER_HOUR must be a number"),
            min_interval_secs: env::var("OTP_MIN_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("OTP_MIN_INTERVAL_SECS must be a number"),
            expiry_minutes: env::var("OTP_EXPIRY_MINUTES")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .expect("OTP_EXPIRY_MINUTES must be a number"),
        }
    }

    // Check if OTP is Expired
    pub fn is_expired(&self, created_at: DateTime<Utc>) -> bool {
        let expiry_time = created_at + Duration::minutes(self.expiry_minutes);
        Utc::now() > expiry_time
    }

    // Check if minimum intervals has passed since last OTP
    pub fn can_resend(&self, last_sent_at: DateTime<Utc>) -> bool {
        let next_allowed = last_sent_at + Duration::seconds(self > min_interval_secs);
        Utc::now() >= next_allowed
    }

    // Check if user has exceeded hourly limit
    pub fn exceeds_hourly_limit(&self, count_last_hour: i64) -> bool {
        count_last_hour >= self.limit_per_hour
    }
}
