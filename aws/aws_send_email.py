import csv
import sqlite3
import boto3
import html2text
import argparse
import sys
import os
import tempfile

# --- CONFIGURATION (Load from environment variables) ---
SENDER = os.environ.get('SES_SENDER')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
TEST_EMAIL = os.environ.get('SES_TEST_EMAIL')
CONTACT_LIST_NAME = os.environ.get('SES_CONTACT_LIST')
S3_BUCKET = os.environ.get('SES_S3_BUCKET')
DB_FILE = os.environ.get('DB_FILE', 'email_tracker.db')

# Validate required environment variables
required_vars = ['SES_SENDER', 'SES_TEST_EMAIL', 'SES_CONTACT_LIST', 'SES_S3_BUCKET']
missing_vars = [var for var in required_vars if not os.environ.get(var)]
if missing_vars:
    print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
    sys.exit(1)
# -----------------------------------

def init_db():
    """Initialize SQLite database and create subscriptions table if it doesn't exist."""
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
    print(f"✅ Database initialized at: {os.path.abspath(DB_FILE)}")

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
        s3_uri = f"s3://{S3_BUCKET}/import_list.csv"
        print(f"✅ Uploaded to {s3_uri}")
        return s3_uri
    except Exception as e:
        print(f"❌ Failed to upload to S3: {e}")
        return None

def import_to_ses(s3_uri):
    """Import contacts to AWS SES contact list using SESv2."""
    sesv2 = boto3.client('sesv2', region_name=AWS_REGION)
    s3 = boto3.client('s3', region_name=AWS_REGION)
    try:
        # Download CSV from S3 to temp file
        with tempfile.NamedTemporaryFile(mode='w+b', suffix='.csv', delete=False) as tmp:
            temp_path = tmp.name
        s3.download_file(S3_BUCKET, 'import_list.csv', temp_path)

        # Parse CSV and create contacts individually
        with open(temp_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row['emailAddress']
                sesv2.create_contact(
                    ContactListName=CONTACT_LIST_NAME,
                    EmailAddress=email
                )
        print(f"📥 Imported contacts to AWS SES contact list: {CONTACT_LIST_NAME}")
        os.unlink(temp_path)
        return True
    except Exception as e:
        print(f"❌ Failed to import to AWS SES: {e}")
        if 'temp_path' in locals():
            try:
                os.unlink(temp_path)
            except:
                pass
        return None

def fetch_aws_contacts_to_csv():
    """Download AWS SES contact list and save as aws_list.csv."""
    sesv2 = boto3.client("sesv2", region_name=AWS_REGION)
    all_contacts = []
    next_token = None
    try:
        while True:
            params = {'ContactListName': CONTACT_LIST_NAME}
            if next_token:
                params['NextToken'] = next_token
            response = sesv2.list_contacts(**params)
            all_contacts.extend(response.get('Contacts', []))
            next_token = response.get('NextToken')
            if not next_token:
                break
        with open('aws_list.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['emailAddress', 'unsubscribeAll'])
            for contact in all_contacts:
                writer.writerow([contact['EmailAddress'], 'false'])
        print(f"✅ Downloaded {len(all_contacts)} contacts from AWS SES to aws_list.csv")
        return len(all_contacts)
    except Exception as e:
        print(f"❌ Failed to fetch AWS contacts: {e}")
        return 0

def save_new_subscribers_to_csv(new_subscribers, filename='new_subscribers.csv'):
    """Save a set of new email subscribers to CSV in AWS SES format."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['emailAddress', 'unsubscribeAll'])
        for email in new_subscribers:
            writer.writerow([email, 'false'])
    print(f"✅ Saved {len(new_subscribers)} new subscribers to {filename}")
    return filename

def read_emails(filename):
    """Read emails from CSV file, return as set of lowercase emails.
    Handles BOM, different encodings, and various column names."""
    emails = set()
    try:
        with open(filename, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                print(f"⚠️ No headers found in {filename}")
                return set()

            # Find the email column (case-insensitive)
            email_col = None
            for col in reader.fieldnames:
                if col.strip().lower() in ['email', 'emailaddress', 'email_address']:
                    email_col = col
                    break

            # If no standard email column, use first column
            if email_col is None:
                email_col = reader.fieldnames[0]
                print(f"ℹ️ Using first column '{email_col}' as email in {filename}")

            for row in reader:
                email = row.get(email_col, '').strip().lower()
                if email:
                    emails.add(email)
        print(f"📧 Read {len(emails)} emails from {filename}")
        return emails
    except FileNotFoundError:
        print(f"❌ File not found: {filename}")
        return set()
    except Exception as e:
        print(f"❌ Error reading {filename}: {e}")
        return set()

def read_html(path):
    """Read pre-compiled HTML file"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"❌ HTML file not found: {path}")
        sys.exit(1)

def html_to_text(html):
    """Convert HTML to plain text"""
    h = html2text.HTML2Text()
    h.ignore_links = True
    h.ignore_images = True
    return h.handle(html).strip()

def sync_subscriptions():
    """Synchronize Substack, AWS SES, and Database using your 5 rules.
    Returns: set of NEW email subscribers to add to AWS SES."""
    substack_emails = read_emails('substack_list.csv')
    aws_emails = read_emails('aws_list.csv')

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT email, substack_subscribed, ses_subscribed FROM subscriptions")
    db_state = {}
    for email, substack_sub, ses_sub in cursor.fetchall():
        db_state[email.lower()] = (bool(substack_sub), bool(ses_sub))

    new_subscribers = set()

    # ===== RULE 1 =====
    # If email exists in Substack and NEITHER the database NOR AWS SES list:
    # --> Insert into database and add to NEW subscribers set
    for email in substack_emails:
        email_lower = email.lower()
        if email_lower not in db_state and email_lower not in aws_emails:
            cursor.execute(
                "INSERT INTO subscriptions (email, substack_subscribed, ses_subscribed) VALUES (?, ?, ?)",
                (email_lower, True, True)
            )
            new_subscribers.add(email_lower)

    # ===== NEW RULE =====
    # If email exists in Substack + Database but NOT in AWS SES:
    # --> Add to NEW subscribers set (force upload to AWS)
    for email in substack_emails:
        email_lower = email.lower()
        if email_lower in db_state and email_lower not in aws_emails:
            new_subscribers.add(email_lower)

    # ===== RULE 2 =====
    # If email does NOT EXIST in Substack, IS in Database, AND IS in AWS SES list:
    # --> Unmark email is in Substack in Database
    for email in aws_emails:
        email_lower = email.lower()
        if email_lower in db_state:
            s, k = db_state[email_lower]
            if email_lower not in substack_emails and s:
                cursor.execute(
                    "UPDATE subscriptions SET substack_subscribed = FALSE WHERE email = ?",
                    (email_lower,)
                )

    # ===== RULE 4 =====
    # If email is in Substack AND AWS SES list but NOT marked in database:
    # --> Mark it in Database for AWS SES
    for email in substack_emails & aws_emails:
        email_lower = email.lower()
        if email_lower in db_state:
            s, k = db_state[email_lower]
            if not k:
                cursor.execute(
                    "UPDATE subscriptions SET ses_subscribed = TRUE WHERE email = ?",
                    (email_lower,)
                )
        else:
            # Email not in DB at all
            cursor.execute(
                "INSERT INTO subscriptions (email, substack_subscribed, ses_subscribed) VALUES (?, ?, ?)",
                (email_lower, True, True)
            )
            new_subscribers.add(email_lower)

    # ===== RULE 5 =====
    # If email is in Substack, in Database as SES subscriber, BUT NOT in actual SES list:
    # --> Unmark as SES subscriber in Database
    for email in substack_emails:
        email_lower = email.lower()
        if email_lower in db_state:
            s, k = db_state[email_lower]
            if k and email_lower not in aws_emails:
                cursor.execute(
                    "UPDATE subscriptions SET ses_subscribed = FALSE WHERE email = ?",
                    (email_lower,)
                )

    conn.commit()
    conn.close()
    return new_subscribers

def send_email(html_content, recipient, subject, sesv2_client):
    """Send HTML email via AWS SES v2 with contact list management."""
    sesv2 = boto3.client("sesv2", region_name=AWS_REGION)
    text_content = html_to_text(html_content)

    # Add manual unsubscribe link to HTML
    unsubscribe_link = f"https://{AWS_REGION}.v2.email.unsubscribe.amazonaws.com/?listName={CONTACT_LIST_NAME}&recipient={recipient}"
    html_with_unsubscribe = f"{html_content}<p style='font-size:12px;color:#666;'>Not interested? <a href='{unsubscribe_link}'>Unsubscribe</a></p>"

    try:
        response = sesv2.send_email(
            FromEmailAddress=SENDER,
            Destination={
                'ToAddresses': [recipient]
            },
            Content={
                'Simple': {
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': text_content,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': html_with_unsubscribe,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            },
            ListManagementOptions={
                'ContactListName': CONTACT_LIST_NAME
            }
        )
        return response["MessageId"]
    except Exception as e:
        print(f"❌ Failed to send to {recipient}: {e}")
        return None

def main():
    init_db()
    sesv2_client = boto3.client("sesv2", region_name=AWS_REGION)

    fetch_aws_contacts_to_csv()
    new_subscribers = sync_subscriptions()
    print(f"📊 Synced subscriptions. NEW subscribers: {len(new_subscribers)}")

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

    subject = ""
    while not subject:
        subject = input("Enter Email Subject in Line Below: ").strip()
        if not subject:
            print("❌ Subject cannot be empty. Please try again.")

    recipients = read_emails('aws_list.csv')
    if not recipients:
        print("ℹ️ No recipients in aws_list.csv, falling back to substack_list.csv")
        recipients = read_emails('substack_list.csv')
        if not recipients:
            print("❌ No valid emails in substack_list.csv")
            sys.exit(1)

    confirmation = input("Type 'substack test' for test or 'substack official' to send: ").strip()

    if confirmation == "substack test":
        print(f"🧪 TEST MODE: Sending to {TEST_EMAIL} only")
        message_id = send_email(html_content, TEST_EMAIL, subject, sesv2_client)
        if message_id:
            print(f"✅ Test sent to {TEST_EMAIL} (MessageId: {message_id})")
        else:
            print(f"❌ Failed to send test email to {TEST_EMAIL}")
    elif confirmation == "substack official":
        print(f"📢 OFFICIAL MODE: Sending to {len(recipients)} recipients")
        for email in recipients:
            message_id = send_email(html_content, email, subject, sesv2_client)
            if message_id:
                print(f"✅ Sent to {email} (MessageId: {message_id})")
            else:
                print(f"❌ Failed to send to {email}")
    else:
        print("❌ Error: Invalid confirmation")

if __name__ == "__main__":
    main()
