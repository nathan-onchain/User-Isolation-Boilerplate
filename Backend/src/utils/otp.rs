use lettre::message::{Message, SinglePart};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use std::env;
use rand::{thread_rng, Rng};


pub fn generate_otp() -> String {
    let mut rng = thread_rng();
    let otp: u32 = rng.gen_range(100000..999999);
    otp.to_string()
}

// Build mailer function
pub fn build_mailer() -> SmtpTransport {

    // Load credentials from env
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set.");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS must be set");
    let smtp_host = env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".to_string());
    let smtp_port: u16 = env::var("SMTP_PORT").unwrap_or_else(|_| "587".to_string())
        .parse()
        .expect("SMTP_PORT must be a number");

    let creds = Credentials::new(smtp_user, smtp_pass);

    SmtpTransport::starttls_relay(&smtp_host)
        .unwrap()
        .port(smtp_port)
        .credentials(creds)
        .build()

}


// Send OTP function
pub fn send_otp_email(to: &str, otp: &str) -> anyhow::Result<()> {

    let from_address = env::var("SMTP_FROM").expect("SMTP_FROM must be set");

    let email = Message::builder()
        .from(from_address.parse()?)
        .to(to.parse()?)
        .subject("Your password reset code")
        .singlepart(
            SinglePart::plain(format!(
                "Hello, \n\nYour OTP code is: {}\n\nIt expires in 10 minutes. \n\nIf you did not request this, please ignore.",
                otp
            ))
        )?;

        let mailer = build_mailer();
        mailer.send(&email)?;

        println!("📧 Sent OTP {otp} to {to}"); // Debug log only!

        match mailer.send(&email) {
            Ok(response) => {
                println!("✅ Email sent! Server response: {:?}", response);
                Ok(())
            }
            Err(err) => {
                eprintln!("❌ Failed to send email: {:?}", err);
                Err(err.into())
            }
        }
}