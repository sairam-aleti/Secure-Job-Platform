"""
FortKnox Platform — Styled HTML Email Templates
All emails use inline styles for maximum email client compatibility.
"""

BRAND_BLUE = "#0A66C2"
BRAND_DARK = "#0C2E4C"
BRAND_LIGHT_BG = "#EBF4FF"

def _base_wrapper(header_content: str, body_content: str, footer_content: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>FortKnox</title></head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:40px 16px;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- HEADER -->
        <tr><td style="background:{BRAND_BLUE};padding:24px 32px;text-align:center;">
          <div style="color:#ffffff;font-size:20px;font-weight:600;letter-spacing:1.5px;">FortKnox</div>
          <div style="color:#85B7EB;font-size:11px;text-transform:uppercase;letter-spacing:2px;margin-top:4px;">Secure Job Platform</div>
        </td></tr>

        <!-- BODY -->
        <tr><td style="background:#ffffff;padding:32px;">
          {body_content}
        </td></tr>

        <!-- FOOTER -->
        <tr><td style="background:#f9f9f9;border-top:1px solid #eee;padding:20px 32px;text-align:center;">
          {footer_content}
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _standard_footer() -> str:
    return """
<p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#333;">Stay Secure — FortKnox Team</p>
<p style="margin:0;font-size:11px;color:#999;">fortknox914@gmail.com &middot; This is an automated message, do not reply.</p>
"""


def get_otp_email_html(name: str, otp_code: str) -> str:
    """Styled HTML for login OTP verification email."""
    body = f"""
<p style="margin:0 0 6px;font-size:15px;color:#333;">Hello, <strong style="color:{BRAND_DARK};">{name}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#555;line-height:1.6;">We received a login request for your FortKnox account. Use the verification code below to complete your sign-in.</p>

<!-- OTP BOX -->
<div style="background:{BRAND_LIGHT_BG};border:1.5px dashed #378ADD;border-radius:10px;padding:24px 20px;text-align:center;margin-bottom:24px;">
  <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{BRAND_BLUE};font-weight:600;margin-bottom:12px;">Your Verification Code</div>
  <div style="font-size:36px;font-weight:700;letter-spacing:0.2em;color:#0C447C;font-family:'Courier New',monospace;">{otp_code}</div>
  <div style="font-size:12px;color:#777;margin-top:10px;">&#9201; Expires in 2 minutes</div>
</div>

<!-- WARNING BOX -->
<div style="border-left:3px solid #EF9F27;background:#FFF8EC;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:24px;">
  <span style="font-size:14px;">&#9888;&#65039;</span>
  <span style="font-size:13px;color:#8B5A00;line-height:1.5;"> If you did not attempt to log in, ignore this email and consider changing your password immediately.</span>
</div>

<!-- SECURITY TIPS -->
<div style="border-top:1px solid #eee;padding-top:16px;">
  <p style="margin:0 0 6px;font-size:12px;color:#666;">&#128274; FortKnox will never ask for your OTP via phone or chat.</p>
  <p style="margin:0;font-size:12px;color:#666;">&#128100; This code is valid for one-time use only.</p>
</div>
"""
    return _base_wrapper("", body, _standard_footer())


def get_registration_otp_html(name: str, otp_code: str) -> str:
    """Styled HTML for registration email verification."""
    body = f"""
<p style="margin:0 0 6px;font-size:15px;color:#333;">Hello, <strong style="color:{BRAND_DARK};">{name}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#555;line-height:1.6;">Thank you for registering with FortKnox! Use the code below to verify your email address and complete your registration.</p>

<div style="background:{BRAND_LIGHT_BG};border:1.5px dashed #378ADD;border-radius:10px;padding:24px 20px;text-align:center;margin-bottom:24px;">
  <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{BRAND_BLUE};font-weight:600;margin-bottom:12px;">Your Verification Code</div>
  <div style="font-size:36px;font-weight:700;letter-spacing:0.2em;color:#0C447C;font-family:'Courier New',monospace;">{otp_code}</div>
  <div style="font-size:12px;color:#777;margin-top:10px;">&#9201; Expires in 10 minutes</div>
</div>

<div style="border-left:3px solid #EF9F27;background:#FFF8EC;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:24px;">
  <span style="font-size:14px;">&#9888;&#65039;</span>
  <span style="font-size:13px;color:#8B5A00;"> If you did not create this account, please ignore this email.</span>
</div>

<div style="border-top:1px solid #eee;padding-top:16px;">
  <p style="margin:0 0 6px;font-size:12px;color:#666;">&#128274; FortKnox will never ask for your OTP via phone or chat.</p>
  <p style="margin:0;font-size:12px;color:#666;">&#128100; This code is valid for one-time use only.</p>
</div>
"""
    return _base_wrapper("", body, _standard_footer())


def get_password_reset_html(name: str, otp_code: str) -> str:
    """Styled HTML for password reset email."""
    body = f"""
<p style="margin:0 0 6px;font-size:15px;color:#333;">Hello, <strong style="color:{BRAND_DARK};">{name}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#555;line-height:1.6;">We received a request to reset your FortKnox password. Use the code below to proceed. If you did not request this, no action is needed.</p>

<div style="background:{BRAND_LIGHT_BG};border:1.5px dashed #378ADD;border-radius:10px;padding:24px 20px;text-align:center;margin-bottom:24px;">
  <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{BRAND_BLUE};font-weight:600;margin-bottom:12px;">Password Reset Code</div>
  <div style="font-size:36px;font-weight:700;letter-spacing:0.2em;color:#0C447C;font-family:'Courier New',monospace;">{otp_code}</div>
  <div style="font-size:12px;color:#777;margin-top:10px;">&#9201; Expires in 2 minutes</div>
</div>

<div style="border-left:3px solid #dc2626;background:#FFF5F5;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:24px;">
  <span style="font-size:14px;">&#128721;</span>
  <span style="font-size:13px;color:#7f1d1d;"> Do not share this code with anyone. FortKnox support will never ask for this code.</span>
</div>

<div style="border-top:1px solid #eee;padding-top:16px;">
  <p style="margin:0 0 6px;font-size:12px;color:#666;">&#128274; FortKnox will never ask for your OTP via phone or chat.</p>
  <p style="margin:0;font-size:12px;color:#666;">&#128100; This code is valid for one-time use only.</p>
</div>
"""
    return _base_wrapper("", body, _standard_footer())


def get_suspension_html(name: str, reason: str = "violation of platform policies") -> str:
    """Styled HTML for account suspension notice."""
    body = f"""
<p style="margin:0 0 6px;font-size:15px;color:#333;">Hello, <strong style="color:{BRAND_DARK};">{name}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#555;line-height:1.6;">Your FortKnox account has been suspended due to <strong>{reason}</strong>.</p>

<div style="border-left:3px solid #dc2626;background:#FFF5F5;border-radius:0 8px 8px 0;padding:16px;margin-bottom:24px;">
  <p style="margin:0;font-size:13px;color:#7f1d1d;line-height:1.6;">If you believe this is a mistake, please contact our support team at <strong>fortknox914@gmail.com</strong> with your account details and a brief explanation.</p>
</div>

<div style="border-top:1px solid #eee;padding-top:16px;">
  <p style="margin:0;font-size:12px;color:#666;">&#128274; This action was taken by our platform moderation team following our security protocols.</p>
</div>
"""
    return _base_wrapper("", body, _standard_footer())


def get_admin_approval_html(name: str) -> str:
    """Styled HTML for admin account approval notification."""
    body = f"""
<p style="margin:0 0 6px;font-size:15px;color:#333;">Hello, <strong style="color:{BRAND_DARK};">{name}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#555;line-height:1.6;">Your FortKnox Admin account has been approved. You now have full access to the Admin Panel.</p>

<div style="background:#F0FFF4;border:1.5px dashed #22c55e;border-radius:10px;padding:20px;text-align:center;margin-bottom:24px;">
  <div style="font-size:28px;margin-bottom:8px;">&#9989;</div>
  <div style="font-size:14px;font-weight:600;color:#166534;">Account Approved</div>
  <div style="font-size:12px;color:#555;margin-top:6px;">You can now log in and access the Admin Panel.</div>
</div>

<div style="border-top:1px solid #eee;padding-top:16px;">
  <p style="margin:0 0 6px;font-size:12px;color:#666;">&#128274; Use your admin credentials to log in at the FortKnox platform.</p>
  <p style="margin:0;font-size:12px;color:#666;">&#128100; Your role and permissions have been configured by the Superadmin.</p>
</div>
"""
    return _base_wrapper("", body, _standard_footer())
