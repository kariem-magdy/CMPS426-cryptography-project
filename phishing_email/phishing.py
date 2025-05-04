import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os

def send_phishing_emails(email_list_path, attachment_path):
    # Read victim emails
    with open(email_list_path, 'r') as f:
        victim_emails = [line.strip() for line in f.readlines()]
    
    sender_email = "ghanemmariam26@gmail.com"
    sender_password = "gqbv sqfp lclx xnmu"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    # Open connection once
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)

    for recipient in victim_emails:
        msg = MIMEMultipart("mixed")
        msg['From'] = f"Vodafone Recruitment Team <{sender_email}>"
        msg['To'] = recipient
        msg['Subject'] = "Invitation to the next stage – _VOIS Explore Internship 2025"
        msg.add_header("List-Unsubscribe", f"<mailto:{sender_email}?subject=unsubscribe>")

        # Text and HTML bodies
        body = """Dear Candidate,

We are glad that you are progressing in your Vodafone assessment journey, and we would like to invite you to a virtual interview & gamified pattern challenge.

Please download the software attached to this email and install it on your computer. The software is a virtual interview platform that will allow you to complete the interview and gamified pattern challenge.

Deadline to submit both assessments: 6 May 2025, 23:59

Further instructions on how to complete the interview are provided once you login.

Kind regards,
Your Vodafone Recruitment Team
"""

        html = """
<!DOCTYPE html>
<html lang="en">
  <head><meta charset="UTF-8"><title>VOIS Explore Internship 2025</title></head>
  <body style="font-family: Arial, sans-serif; font-size: 15px; color: #222; background-color: #f4f4f4; margin: 0; padding: 20px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px;">
      <tr>
        <td>
          <h2 style="color: #e60000; margin-top: 0;">_VOIS Explore Internship 2025</h2>
          <p>Dear Candidate,</p>
          <p>We are glad that you are progressing in your <strong>Vodafone</strong> assessment journey, and we would like to invite you to a virtual interview & gamified pattern challenge.</p>
          <p><strong>Please download the software attached to this email and install it on your computer. </strong>The software is a virtual interview platform that will allow you to complete the interview and gamified pattern challenge. </p>
          <p><strong>Deadline to submit both assessments: 6 May 2025, 23:59</strong></p>
          <p>Further instructions on how to complete the interview are provided once you login.</p>
          <p>If you have any questions or need adjustments, please contact our Recruitment Team.</p>
          <p>Kind regards,<br><strong>Mariam Ghanem <br> Vodafone Recruitment Team</br></strong></p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        # Attach plain text and HTML
        # msg.attach(MIMEText(body, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Add the attachment
        if attachment_path:
            try:
                with open(attachment_path, "rb") as attachment_file:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment_file.read())
                encoders.encode_base64(part)
                filename = os.path.basename(attachment_path)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename={filename}",
                )
                msg.attach(part)
            except Exception as e:
                print(f"[!] Failed to attach file: {e}")
                continue

        # Send the message
        try:
            server.sendmail(sender_email, recipient, msg.as_string())
            print(f"[✓] Email sent to {recipient}")
        except Exception as e:
            print(f"[!] Failed to send to {recipient}: {e}")

    server.quit()

# Example usage
send_phishing_emails(r"E:\University\Materials\7 - Year 6 (2024 - 2025)\Semester 2\Security\Project\CMPS426-cryptography-project\phishing_email\victim_emails.txt", 
                    r"E:\University\Materials\7 - Year 6 (2024 - 2025)\Semester 2\Security\Project\CMPS426-cryptography-project\phishing_email\example_random.bin")  # Replace with your actual file
