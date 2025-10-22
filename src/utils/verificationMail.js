export const generateVerificationMail = (email, otp) => {
  return {
    from: process.env.SENDER_EMAIL,
    to: email,
    subject: 'Welcome to My Authentication Project 🎉',
    html: `
      <div style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
          <h2 style="color: #007bff; text-align: center;">Welcome to My Website</h2>
          <p style="font-size: 16px; color: #333;">
            Hi there 👋,<br><br>
            Thank you for registering on our platform! To complete your registration, please verify your account using the OTP below:
          </p>
          <div style="text-align: center; margin: 25px 0;">
            <span style="font-size: 24px; font-weight: bold; color: #007bff; letter-spacing: 2px;">
              ${otp}
            </span>
          </div>
          <p style="font-size: 15px; color: #555;">
            This OTP will expire in <strong>5 minutes</strong>. Please do not share it with anyone.
          </p>
          <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
          <p style="font-size: 13px; color: #888; text-align: center;">
            © ${new Date().getFullYear()} My Authentication Project. All rights reserved.
          </p>
        </div>
      </div>
    `
  }
}


export const generatePasswordResetMail = (email, otp) => {
  return {
    from: process.env.SENDER_EMAIL,
    to: email,
    subject: 'Password Reset Request 🔒',
    html: `
      <div style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
          <h2 style="color: #ff6600; text-align: center;">Password Reset Request</h2>
          <p style="font-size: 16px; color: #333;">
            Hi there 👋,<br><br>
            We received a request to reset your password. Please use the OTP below to verify your request and reset your password:
          </p>
          <div style="text-align: center; margin: 25px 0;">
            <span style="font-size: 24px; font-weight: bold; color: #ff6600; letter-spacing: 2px;">
              ${otp}
            </span>
          </div>
          <p style="font-size: 15px; color: #555;">
            This OTP will expire in <strong>5 minutes</strong>. If you didn’t request a password reset, please ignore this email — your account is safe.
          </p>
          <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
          <p style="font-size: 13px; color: #888; text-align: center;">
            © ${new Date().getFullYear()} My Authentication Project. All rights reserved.
          </p>
        </div>
      </div>
    `
  }
}

