import csv
import sqlite3
import sys
import os

# --- CONFIGURATION ---
DB_FILE = "email_tracker.db"
SUBSTACK_CSV_FILE = "substack_list.csv"
MAILERLITE_CSV_FILE = "mailerlite_list.csv"
OUTPUT_FILE = "New_SysCoder_Challenge_Subscribers.csv"
GROUP_NAME = "The SysCoder Challenge"

def init_db():
    """Initialize database with backward compatibility."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            email TEXT PRIMARY KEY,
            substack_subscribed BOOLEAN DEFAULT FALSE,
            ses_subscribed BOOLEAN DEFAULT FALSE,
            mailerlite_subscribed BOOLEAN DEFAULT FALSE
        )
    ''')
    cursor.execute("PRAGMA table_info(subscriptions)")
    if not any(col[1] == 'mailerlite_subscribed' for col in cursor.fetchall()):
        cursor.execute('ALTER TABLE subscriptions ADD COLUMN mailerlite_subscribed BOOLEAN DEFAULT FALSE')
        cursor.execute('UPDATE subscriptions SET mailerlite_subscribed = ses_subscribed')
    conn.commit()
    conn.close()
    print(f"✅ Database ready")

def read_emails(filename):
    """Read emails from CSV file."""
    emails = set()
    try:
        with open(filename, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return set()
            email_col = None
            for col in reader.fieldnames:
                if col.strip().lower() in ['email', 'emailaddress', 'email_address']:
                    email_col = col
                    break
            if email_col is None:
                email_col = reader.fieldnames[0]
            for row in reader:
                email = row.get(email_col, '').strip().lower()
                if email:
                    emails.add(email)
        print(f"📧 Read {len(emails)} emails from {filename}")
        return emails
    except FileNotFoundError:
        print(f"⚠️ File not found: {filename}")
        return set()
    except Exception as e:
        print(f"❌ Error reading {filename}: {e}")
        return set()

def get_unsubscribed_emails():
    """Get emails marked as unsubscribed in database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM subscriptions WHERE mailerlite_subscribed = FALSE")
    unsubscribed = {row[0].lower() for row in cursor.fetchall()}
    conn.close()
    return unsubscribed

def generate_new_subscribers():
    """Generate list of new subscribers to add."""
    init_db()

    # Read existing subscribers
    substack_emails = read_emails(SUBSTACK_CSV_FILE)
    mailerlite_emails = read_emails(MAILERLITE_CSV_FILE)

    # Get previously unsubscribed emails
    unsubscribed_emails = get_unsubscribed_emails()

    # Find new subscribers (in Substack but not in MailerLite)
    new_emails = substack_emails - mailerlite_emails

    # Filter out previously unsubscribed
    new_emails = new_emails - unsubscribed_emails

    # Write to output file
    if new_emails:
        with open(OUTPUT_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['email'])
            for email in sorted(new_emails):
                writer.writerow([email])
        print(f"✅ Generated {OUTPUT_FILE} with {len(new_emails)} new subscribers")
        return len(new_emails)
    else:
        print("ℹ️ No new subscribers to add")
        return 0

if __name__ == "__main__":
    count = generate_new_subscribers()
    print(f"📊 Total new subscribers ready for upload: {count}")
