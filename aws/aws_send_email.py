import csv
import sqlite3
import boto3
import html2text
import argparse
import sys
import os
import tempfile

# --- CONFIGURATION (via environment variables) ---
SENDER = os.environ.get('SES_SENDER_EMAIL', 'noreply@yourdomain.com')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
TEST_EMAIL = os.environ.get('SES_TEST_EMAIL', 'test@yourdomain.com')
CONTACT_LIST_NAME = os.environ.get('SES_CONTACT_LIST', 'YourContactList')
S3_BUCKET = os.environ.get('SES_S3_BUCKET', 'your-ses-contacts-bucket')
DB_FILE = os.environ.get('DB_FILE', 'email_tracker.db')
# -----------------------------------

def init_db():
    """Initialize SQLite database and create subscriptions table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            email TEXT PRIMARY KEY,
            substack_subscribed BOOLEAN DEFAULT FALSE,
            ses_subscribed BOOLEAN DEFAULT FALSE
        )
    ''')
    conn.commit()
    conn.close()

def upload_to_s3(local_file):
    """Upload a file to S3 bucket for AWS SES import."""
    s3 = boto3.client('s3', region_name=AWS_REGION)
    try:
        s3.upload_file(
            local_file,
            S3_BUCKET,
            'import_list.csv',
            ExtraArgs={'ContentType': 'text/csv'}
        )
        return f"s3://{S3_BUCKET}/import_list.csv"
    except Exception as e:
        print(f"Failed to upload to S3: {e}")
        return None

def import_to_ses(s3_uri):
    """Import contacts to AWS SES contact list using SESv2."""
    sesv2 = boto3.client('sesv2', region_name=AWS_REGION)
    try:
        with tempfile.NamedTemporaryFile(mode='w+b', suffix='.csv', delete=False) as tmp:
            temp_path = tmp.name
        # Download and process CSV
        return True
    except Exception as e:
        print(f"Failed to import to AWS SES: {e}")
        return None

def fetch_aws_contacts_to_csv():
    """Download AWS SES contact list and save as CSV."""
    sesv2 = boto3.client("sesv2", region_name=AWS_REGION)
    # Implementation omitted for brevity
    pass

def save_new_subscribers_to_csv(new_subscribers, filename='new_subscribers.csv'):
    """Save new subscribers to CSV in AWS SES format."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['emailAddress', 'unsubscribeAll'])
        for email in new_subscribers:
            writer.writerow([email, 'false'])
    return filename

def read_emails(filename):
    """Read emails from CSV file, return as set."""
    emails = set()
    try:
        with open(filename, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Parse emails from CSV
            pass
        return emails
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return set()

def read_html(path):
    """Read pre-compiled HTML file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"HTML file not found: {path}")
        sys.exit(1)

def html_to_text(html):
    """Convert HTML to plain text."""
    h = html2text.HTML2Text()
    h.ignore_links = True
    h.ignore_images = True
    return h.handle(html).strip()

def sync_subscriptions():
    """Synchronize Substack, AWS SES, and Database."""
    substack_emails = read_emails('substack_list.csv')
    aws_emails = read_emails('aws_list.csv')
    # Sync logic between sources
    return set()

def send_email(html_content, recipient, subject, sesv2_client):
    """Send HTML email with unsubscribe endpoint."""
    text_content = html_to_text(html_content)
    unsubscribe_link = f"https://your-api-gateway.execute-api.{AWS_REGION}.amazonaws.com/prod/unsubscribe?email={recipient}&list={CONTACT_LIST_NAME}"

    html_with_unsubscribe = f"""
    {html_content}
    <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #666;">
      Not interested? <a href="{unsubscribe_link}">Unsubscribe</a>
    </div>
    """

    try:
        response = sesv2_client.send_email(
            FromEmailAddress=SENDER,
            Destination={'ToAddresses': [recipient]},
            ConfigurationSetName='my-first-configuration-set',
            Content={
                'Simple': {
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {
                        'Text': {'Data': text_content, 'Charset': 'UTF-8'},
                        'Html': {'Data': html_with_unsubscribe, 'Charset': 'UTF-8'}
                    }
                }
            },
            ListManagementOptions={'ContactListName': CONTACT_LIST_NAME}
        )
        return response["MessageId"]
    except Exception as e:
        print(f"Failed to send to {recipient}: {e}")
        return None

def main():
    init_db()
    sesv2_client = boto3.client("sesv2", region_name=AWS_REGION)

    fetch_aws_contacts_to_csv()
    new_subscribers = sync_subscriptions()
    print(f"Synced subscriptions. NEW subscribers: {len(new_subscribers)}")

    if new_subscribers:
        csv_file = save_new_subscribers_to_csv(new_subscribers)
        s3_uri = upload_to_s3(csv_file)
        if s3_uri:
            import_to_ses(s3_uri)
            fetch_aws_contacts_to_csv()

    parser = argparse.ArgumentParser(description="Send HTML email via Amazon SES")
    parser.add_argument("file", help="Path to pre-compiled HTML file")
    args = parser.parse_args()

    html_content = read_html(args.file)
    subject = input("Enter Email Subject: ").strip()
    recipients = read_emails('aws_list.csv') or read_emails('substack_list.csv')

    confirmation = input("Type 'test' or 'official' to send: ").strip()

    if confirmation == "test":
        message_id = send_email(html_content, TEST_EMAIL, subject, sesv2_client)
        print(f"Test sent to {TEST_EMAIL}" if message_id else f"Failed to send test")
    elif confirmation == "official":
        for email in recipients:
            message_id = send_email(html_content, email, subject, sesv2_client)
            print(f"Sent to {email}" if message_id else f"Failed to send to {email}")

if __name__ == "__main__":
    main()
