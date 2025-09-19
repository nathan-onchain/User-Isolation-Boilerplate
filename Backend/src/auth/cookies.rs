use actix_web::cookie::{Cookie, SameSite};

/// Create a base empty access_token cookie with proper flags
pub fn base_access_token_cookie() -> Cookie<'static> {
    Cookie::build("access_token", "") // empty value for now
        .path("/")
        .http_only(true)
        .secure(cfg!(not(debug_assertions))) // secure in prod only
        .same_site(SameSite::Lax)
        .finish()
}

/// Update the value of an existing cookie with JWT
pub fn set_access_token(token: &str) -> Cookie<'static> {
    let mut cookie = base_access_token_cookie();
    cookie.set_value(token.to_string());
    cookie
}

/// Clear the cookie (for logout)
pub fn clear_access_token() -> Cookie<'static> {
    let mut cookie = base_access_token_cookie();
    cookie.set_max_age(time::Duration::seconds(0)); // expire immediately
    cookie
}
