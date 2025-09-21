import os
import smtplib
from email.message import EmailMessage

def send_otp_to_email(to_email, otp):
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_APP_PASSWORD')  # e.g., Gmail App Password
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))

    # Safe dev fallback: if creds aren't set, just print the OTP
    if not sender_email or not sender_password:
        print(f"[DEV] OTP for {to_email}: {otp}")
        return

    msg = EmailMessage()
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = sender_email
    msg['To'] = to_email
    msg.set_content(f'Your OTP code is: {otp}')

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
    except Exception as e:
        # Fallback to SSL if STARTTLS fails
        try:
            with smtplib.SMTP_SSL(smtp_server, 465) as smtp:
                smtp.login(sender_email, sender_password)
                smtp.send_message(msg)
        except Exception as e2:
            print(f"Email send failed: {e}; fallback failed: {e2}")
            raise
