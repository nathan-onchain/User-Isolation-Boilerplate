use askama::Template;

#[derive(Template)]
#[template(path = "otp_email.html")]
pub struct OtpEmailTemplate<'a> {
    pub email: &'a str,
    pub otp: &'a str,
    pub expiry_minutes: u32,
}
