"""Comprehensive showcase database seed & evidence generator for ScamAlert.

Creates:
- 108 realistic users across all roles (Admin, Moderator, Trusted Hunter, Active User, Newcomer)
- Universal demo password: 'Password@123' (valid bcrypt hash for all accounts)
- 20 realistic, high-impact Indian fraud reports spanning all 10 categories
- Authentic, crisp graphical evidence images (SMS screenshots, phishing portals,
  WhatsApp chats, UPI debit receipts, flash sale pages) saved in uploads/evidence/<report_id>/
- Real verification votes, comments, tags, history timelines, discussions, and risk breakdowns
"""
import hashlib
import os
import shutil
import sys
import uuid
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import bcrypt
import mysql.connector
from PIL import Image, ImageDraw, ImageFont

from backend.config import parse_db_url

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
UNIVERSAL_PASSWORD = "Password@123"
BCRYPT_ROUNDS = 12
HASHED_PASSWORD = bcrypt.hashpw(UNIVERSAL_PASSWORD.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("utf-8")

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
EVIDENCE_DIR = os.path.join(UPLOAD_DIR, "evidence")

ANONYMOUS_UUID = "00000000-0000-0000-0000-000000000001"


# -----------------------------------------------------------------------------
# Graphical Evidence Image Generators (Pillow)
# -----------------------------------------------------------------------------
def _get_font(size=14, bold=False):
    # Try common Windows TrueType fonts, fall back to default
    candidates = [
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\calibri.ttf",
    ]
    if bold:
        candidates = [
            "C:\\Windows\\Fonts\\segoeuib.ttf",
            "C:\\Windows\\Fonts\\arialbd.ttf",
            "C:\\Windows\\Fonts\\calibrib.ttf",
        ] + candidates
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


def create_sms_evidence(sender="VK-MSDCL", message="Dear Customer, your electricity will be disconnected tonight at 9:30 PM because previous bill was not updated. Please call officer at 9876543210 or pay at http://mahadiscom-billpay.in immediately.", dest_path="sms.png"):
    width, height = 500, 360
    img = Image.new("RGB", (width, height), color=(240, 242, 245))
    draw = ImageDraw.Draw(img)

    f_title = _get_font(16, bold=True)
    f_body = _get_font(14)
    f_small = _get_font(11)

    # Status Bar
    draw.rectangle([0, 0, width, 32], fill=(20, 25, 30))
    draw.text((15, 8), "10:42 AM", fill=(255, 255, 255), font=f_small)
    draw.text((width - 65, 8), "LTE  94%", fill=(255, 255, 255), font=f_small)

    # App Header
    draw.rectangle([0, 32, width, 84], fill=(255, 255, 255))
    draw.line([0, 84, width, 84], fill=(220, 224, 230), width=1)
    draw.text((20, 44), "<", fill=(10, 100, 240), font=f_title)
    draw.ellipse([45, 42, 75, 72], fill=(220, 230, 245))
    draw.text((54, 48), sender[:2], fill=(20, 80, 180), font=f_title)
    draw.text((88, 44), sender, fill=(20, 20, 20), font=f_title)
    draw.text((88, 64), "Verified SMS Sender", fill=(100, 110, 120), font=f_small)

    # Date chip
    draw.text((width // 2 - 30, 100), "Today", fill=(140, 150, 160), font=f_small)

    # Message Bubble
    bubble_x, bubble_y = 20, 125
    bubble_w, bubble_h = width - 40, 175
    draw.rounded_rectangle([bubble_x, bubble_y, bubble_x + bubble_w, bubble_y + bubble_h], radius=12, fill=(255, 255, 255), outline=(210, 215, 225))

    # Message text wrapping
    words = message.split()
    lines = []
    cur = []
    for w in words:
        test = " ".join(cur + [w])
        if len(test) > 52:
            lines.append(" ".join(cur))
            cur = [w]
        else:
            cur.append(w)
    if cur:
        lines.append(" ".join(cur))

    y = bubble_y + 14
    for line in lines:
        if "http" in line:
            parts = line.split("http")
            draw.text((bubble_x + 14, y), parts[0], fill=(30, 30, 30), font=f_body)
            link_txt = "http" + parts[1]
            draw.text((bubble_x + 14 + int(len(parts[0]) * 7.5), y), link_txt, fill=(10, 100, 240), font=f_body)
        else:
            draw.text((bubble_x + 14, y), line, fill=(30, 30, 30), font=f_body)
        y += 22

    draw.text((bubble_x + bubble_w - 60, bubble_y + bubble_h - 22), "10:41 AM", fill=(150, 150, 150), font=f_small)

    # Threat Warning Banner at bottom
    draw.rectangle([0, height - 34, width, height], fill=(255, 235, 235))
    draw.text((15, height - 26), "⚠️ Suspected fraudulent link reported by community", fill=(190, 30, 30), font=f_small)

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    img.save(dest_path, "PNG")
    return dest_path


def create_browser_phishing_evidence(domain="sbi-yono-kycupdate.xyz", brand="STATE BANK OF INDIA", alert_text="URGENT: Update your PAN & Aadhaar to keep YONO Active", dest_path="portal.png"):
    width, height = 560, 400
    img = Image.new("RGB", (width, height), color=(250, 250, 252))
    draw = ImageDraw.Draw(img)

    f_title = _get_font(16, bold=True)
    f_body = _get_font(13)
    f_small = _get_font(11)

    # Browser Window Bar
    draw.rectangle([0, 0, width, 40], fill=(230, 233, 238))
    # Window buttons
    draw.ellipse([14, 14, 24, 24], fill=(255, 95, 86))
    draw.ellipse([30, 14, 40, 24], fill=(255, 189, 46))
    draw.ellipse([46, 14, 56, 24], fill=(39, 201, 63))

    # Address bar
    draw.rounded_rectangle([75, 8, width - 20, 32], radius=6, fill=(255, 255, 255), outline=(200, 205, 215))
    draw.text((85, 12), "⚠️ Not Secure | https://" + domain + "/login.php", fill=(190, 40, 40), font=f_small)

    # Bank Brand Banner
    draw.rectangle([0, 40, width, 95], fill=(26, 68, 128))  # SBI Navy
    draw.text((25, 52), brand, fill=(255, 255, 255), font=f_title)
    draw.text((25, 74), "Internet Banking Verification Gateway", fill=(200, 220, 255), font=f_small)

    # Phishing Warning notice box
    draw.rectangle([25, 110, width - 25, 150], fill=(255, 243, 205), outline=(255, 220, 140))
    draw.text((35, 122), alert_text, fill=(133, 100, 4), font=f_body)

    # Fake Login Form
    form_y = 165
    draw.text((35, form_y), "Username / CIF Number:", fill=(50, 50, 50), font=f_body)
    draw.rounded_rectangle([35, form_y + 20, width - 35, form_y + 48], radius=4, fill=(255, 255, 255), outline=(180, 185, 195))
    draw.text((45, form_y + 26), "Enter your netbanking ID...", fill=(160, 160, 160), font=f_body)

    form_y += 58
    draw.text((35, form_y), "Login Password:", fill=(50, 50, 50), font=f_body)
    draw.rounded_rectangle([35, form_y + 20, width - 35, form_y + 48], radius=4, fill=(255, 255, 255), outline=(180, 185, 195))
    draw.text((45, form_y + 26), "••••••••••••", fill=(100, 100, 100), font=f_body)

    form_y += 58
    draw.text((35, form_y), "Profile Password / Transaction PIN:", fill=(50, 50, 50), font=f_body)
    draw.rounded_rectangle([35, form_y + 20, width - 35, form_y + 48], radius=4, fill=(255, 255, 255), outline=(180, 185, 195))
    draw.text((45, form_y + 26), "Enter 6-digit transaction PIN...", fill=(160, 160, 160), font=f_body)

    # Submit Button
    form_y += 62
    draw.rounded_rectangle([35, form_y, 160, form_y + 36], radius=4, fill=(26, 68, 128))
    draw.text((58, form_y + 8), "SUBMIT & VERIFY", fill=(255, 255, 255), font=f_body)

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    img.save(dest_path, "PNG")
    return dest_path


def create_upi_receipt_evidence(amount="14,500.00", recipient="powerbill.mpeb@ybl", utr="429188402910", dest_path="receipt.png"):
    width, height = 480, 420
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    f_title = _get_font(18, bold=True)
    f_amount = _get_font(28, bold=True)
    f_body = _get_font(13)
    f_small = _get_font(11)

    # Header bar
    draw.rectangle([0, 0, width, 55], fill=(88, 38, 150))  # PhonePe purple
    draw.text((20, 16), "Payment Successful", fill=(255, 255, 255), font=f_title)

    # Success badge
    draw.ellipse([width // 2 - 28, 75, width // 2 + 28, 131], fill=(46, 175, 80))
    draw.text((width // 2 - 10, 88), "✓", fill=(255, 255, 255), font=f_amount)

    # Amount
    draw.text((width // 2 - 70, 145), f"₹{amount}", fill=(20, 20, 20), font=f_amount)
    draw.text((width // 2 - 85, 190), f"Paid to: {recipient}", fill=(80, 80, 80), font=f_body)

    # Receipt table
    y = 230
    draw.line([30, y, width - 30, y], fill=(220, 220, 220), width=1)
    y += 15
    draw.text((35, y), "Transaction ID:", fill=(120, 120, 120), font=f_body)
    draw.text((width - 200, y), f"T{utr[:8]}XX", fill=(30, 30, 30), font=f_body)
    y += 28
    draw.text((35, y), "UPI Ref (UTR):", fill=(120, 120, 120), font=f_body)
    draw.text((width - 200, y), utr, fill=(30, 30, 30), font=f_body)
    y += 28
    draw.text((35, y), "Debited From:", fill=(120, 120, 120), font=f_body)
    draw.text((width - 200, y), "State Bank of India ••4210", fill=(30, 30, 30), font=f_body)
    y += 28
    draw.text((35, y), "Date & Time:", fill=(120, 120, 120), font=f_body)
    draw.text((width - 200, y), "12 Oct 2026, 09:14 PM", fill=(30, 30, 30), font=f_body)

    # Bottom notice
    y += 40
    draw.rectangle([25, y, width - 25, y + 38], fill=(255, 245, 245), outline=(255, 200, 200))
    draw.text((35, y + 10), "⚠️ Disputed Transaction: Reported to 1930 Cyber Helpline", fill=(200, 30, 30), font=f_small)

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    img.save(dest_path, "PNG")
    return dest_path


def create_whatsapp_chat_evidence(contact="HR Pooja (Amazon Part-Time)", dest_path="whatsapp.png"):
    width, height = 500, 420
    img = Image.new("RGB", (width, height), color=(235, 230, 225))  # WhatsApp chat bg
    draw = ImageDraw.Draw(img)

    f_title = _get_font(15, bold=True)
    f_body = _get_font(13)
    f_small = _get_font(10)

    # Top Bar
    draw.rectangle([0, 0, width, 60], fill=(7, 94, 84))
    draw.ellipse([15, 12, 50, 47], fill=(200, 220, 220))
    draw.text((25, 18), "P", fill=(7, 94, 84), font=f_title)
    draw.text((60, 14), contact, fill=(255, 255, 255), font=f_title)
    draw.text((60, 34), "online (+91 88472-39201)", fill=(200, 235, 225), font=f_small)

    y = 80
    # Incoming Message 1
    draw.rounded_rectangle([20, y, width - 100, y + 65], radius=8, fill=(255, 255, 255))
    draw.text((30, y + 8), "Hello! Congratulations! You have been selected", fill=(20, 20, 20), font=f_body)
    draw.text((30, y + 26), "for YouTube Rating task. Daily income ₹2500-₹5000.", fill=(20, 20, 20), font=f_body)
    draw.text((width - 145, y + 46), "11:02 AM", fill=(140, 140, 140), font=f_small)

    y += 80
    # Outgoing Message 1
    draw.rounded_rectangle([100, y, width - 20, y + 48], radius=8, fill=(220, 248, 198))
    draw.text((115, y + 8), "Is this genuine? How do I start?", fill=(20, 20, 20), font=f_body)
    draw.text((width - 65, y + 28), "11:03 AM ✓✓", fill=(100, 150, 100), font=f_small)

    y += 65
    # Incoming Message 2 (The Trap)
    draw.rounded_rectangle([20, y, width - 60, y + 85], radius=8, fill=(255, 255, 255))
    draw.text((30, y + 8), "Trial task complete! Here is your ₹150 reward.", fill=(20, 20, 20), font=f_body)
    draw.text((30, y + 26), "Now for VIP Level 2 (Profit ₹28,000), please", fill=(20, 20, 20), font=f_body)
    draw.text((30, y + 44), "deposit ₹15,000 security to UPI: vip.orders@axl", fill=(180, 20, 20), font=f_body)
    draw.text((width - 105, y + 64), "11:06 AM", fill=(140, 140, 140), font=f_small)

    y += 105
    # Outgoing Message 2
    draw.rounded_rectangle([80, y, width - 20, y + 65], radius=8, fill=(220, 248, 198))
    draw.text((95, y + 8), "I paid ₹15,000! Now dashboard says error and", fill=(20, 20, 20), font=f_body)
    draw.text((95, y + 26), "asking for ₹45,000 more to unlock withdrawal?!", fill=(20, 20, 20), font=f_body)
    draw.text((width - 65, y + 45), "11:42 AM ✓", fill=(100, 150, 100), font=f_small)

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    img.save(dest_path, "PNG")
    return dest_path


def create_ecommerce_deal_evidence(product="iPhone 15 (128 GB) - Starlight", deal_price="₹14,999", original_price="₹79,900", dest_path="deal.png"):
    width, height = 540, 390
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    f_title = _get_font(16, bold=True)
    f_price = _get_font(24, bold=True)
    f_body = _get_font(13)
    f_small = _get_font(11)

    # Top yellow banner (Fake Flipkart style)
    draw.rectangle([0, 0, width, 50], fill=(40, 116, 240))  # Blue
    draw.text((20, 14), "Flipkart Diwali Mega Dhamaka", fill=(255, 255, 255), font=f_title)
    draw.text((width - 110, 16), "⚡ FLASH SALE", fill=(255, 235, 59), font=f_title)

    # Fake URL bar
    draw.rectangle([0, 50, width, 75], fill=(245, 245, 245))
    draw.text((20, 56), "URL: http://flipkart-diwali-dhamaka.shop/deals/iphone15", fill=(180, 30, 30), font=f_small)

    # Product Box
    draw.rectangle([25, 95, 175, 255], fill=(245, 247, 250), outline=(220, 220, 220))
    draw.text((45, 165), "[📱 Mobile Device]", fill=(120, 120, 120), font=f_body)

    # Product details
    draw.text((195, 105), product, fill=(20, 20, 20), font=f_title)
    draw.text((195, 130), "⭐⭐⭐⭐⭐ (14,209 ratings)", fill=(56, 142, 60), font=f_small)

    # Price section
    draw.text((195, 160), deal_price, fill=(33, 33, 33), font=f_price)
    draw.text((320, 168), original_price, fill=(135, 135, 135), font=f_body)
    draw.line([320, 177, 385, 177], fill=(135, 135, 135), width=2)
    draw.text((395, 168), "81% OFF", fill=(56, 142, 60), font=f_title)

    # Fake urgency counter
    draw.rectangle([195, 205, width - 25, 240], fill=(255, 243, 224))
    draw.text((205, 215), "🔥 Hurry! Only 3 units left in stock. Deal ends in 04m:18s", fill=(230, 81, 0), font=f_body)

    # Buy Button
    draw.rectangle([195, 255, 340, 295], fill=(251, 100, 27))
    draw.text((225, 266), "⚡ BUY NOW", fill=(255, 255, 255), font=f_title)

    draw.rectangle([355, 255, 510, 295], fill=(255, 159, 0))
    draw.text((375, 266), "PAY VIA UPI", fill=(255, 255, 255), font=f_title)

    # Warning text
    draw.text((25, 330), "⚠️ Fake clone domain reported. Payment routes to personal UPI ID, no product dispatched.", fill=(200, 30, 30), font=f_body)

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    img.save(dest_path, "PNG")
    return dest_path


# -----------------------------------------------------------------------------
# Seeding Logic
# -----------------------------------------------------------------------------
def seed_database():
    cfg = parse_db_url()
    print(f"Connecting to MySQL on {cfg.get('host')}:{cfg.get('port')} (DB: {cfg.get('database')})...")
    conn = mysql.connector.connect(**cfg, use_pure=True)
    cur = conn.cursor(dictionary=True)

    # 1. Clear dynamic tables in reverse FK order
    print("Clearing dynamic data (posts, votes, evidence, comments, user accounts)...")
    tables_to_clear = [
        "discussion_votes",
        "discussion_replies",
        "website_discussions",
        "appeal_evidence",
        "appeals",
        "risk_score_breakdowns",
        "report_history",
        "report_comments",
        "report_tags",
        "verification_votes",
        "report_evidence",
        "fraud_reports",
        "website_urls",
        "reputation_events",
        "rate_limit_events",
        "audit_events",
    ]
    for tbl in tables_to_clear:
        cur.execute(f"DELETE FROM {tbl}")

    # Delete users except the anonymous sentinel
    cur.execute(f"DELETE FROM users WHERE id != UUID_TO_BIN('{ANONYMOUS_UUID}')")

    # Ensure Anonymous sentinel exists
    cur.execute(
        f"INSERT IGNORE INTO users (id, email, name, password, role, emailVerified, is_active, reputation_score, reputation_tier) "
        f"VALUES (UUID_TO_BIN('{ANONYMOUS_UUID}'), 'anonymous@scamalert.local', 'Anonymous', NULL, 'user', FALSE, TRUE, 0, 'newcomer')"
    )
    conn.commit()

    # Clear disk uploads
    if os.path.exists(EVIDENCE_DIR):
        shutil.rmtree(EVIDENCE_DIR, ignore_errors=True)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    # 2. Seed Users (~108 total)
    print("Seeding 108 users with roles and trust tiers...")

    # Key demo users
    demo_users = [
        # Admins
        ("admin@scamalert.in", "Arjun Mehta", "admin", 98, "moderator"),
        ("kavita.admin@scamalert.in", "Kavita Iyer", "admin", 95, "moderator"),
        # Moderators
        ("moderator@scamalert.in", "Dr. Sunita Rao", "moderator", 92, "moderator"),
        ("priya.sharma@cybercell.gov.in", "Priya Sharma (Cyber Cell)", "moderator", 88, "moderator"),
        ("rajesh.verma@cert-in.org.in", "Rajesh Verma (CERT-In)", "moderator", 86, "moderator"),
        ("ananya.singh@scamalert.in", "Ananya Singh", "moderator", 84, "moderator"),
        ("karthik.subramanian@scamalert.in", "Karthik Subramanian", "moderator", 82, "moderator"),
        ("pooja.deshmukh@cyberlaw.in", "Pooja Deshmukh", "moderator", 80, "moderator"),
        # Trusted Hunters (eligible to vote: rep >= 60)
        ("vikram.hunter@scamalert.in", "Vikram Joshi", "trusted_hunter", 78, "expert"),
        ("rahul.patel@scamalert.in", "Rahul Patel", "trusted_hunter", 76, "expert"),
        ("aditi.rao@scamalert.in", "Aditi Rao", "trusted_hunter", 75, "expert"),
        ("siddharth.nair@scamalert.in", "Siddharth Nair", "trusted_hunter", 74, "expert"),
        ("divya.menon@scamalert.in", "Divya Menon", "trusted_hunter", 72, "expert"),
        ("rohan.malhotra@scamalert.in", "Rohan Malhotra", "trusted_hunter", 70, "expert"),
        ("tanvi.bhatt@scamalert.in", "Tanvi Bhatt", "trusted_hunter", 69, "expert"),
        ("manish.tiwari@scamalert.in", "Manish Tiwari", "trusted_hunter", 68, "expert"),
        ("alok.mishra@scamalert.in", "Alok Mishra", "trusted_hunter", 67, "expert"),
        ("meera.nambiar@scamalert.in", "Meera Nambiar", "trusted_hunter", 66, "expert"),
        ("gaurav.kapoor@scamalert.in", "Gaurav Kapoor", "trusted_hunter", 65, "expert"),
        ("swati.joshi@scamalert.in", "Swati Joshi", "trusted_hunter", 64, "expert"),
        ("harsh.vardhan@scamalert.in", "Harsh Vardhan", "trusted_hunter", 63, "expert"),
        ("snehal.kulkarni@scamalert.in", "Snehal Kulkarni", "trusted_hunter", 62, "expert"),
        ("deepak.sen@scamalert.in", "Deepak Sen", "trusted_hunter", 61, "expert"),
        ("tarun.grover@scamalert.in", "Tarun Grover", "trusted_hunter", 60, "expert"),
        # Active Trusted Users (rep 30-58)
        ("neha.gupta@example.com", "Neha Gupta", "user", 55, "trusted"),
        ("amit.kumar@example.com", "Amit Kumar", "user", 52, "trusted"),
        ("deepa.nair@example.com", "Deepa Nair", "user", 48, "trusted"),
        ("sanjay.verma@example.com", "Sanjay Verma", "user", 45, "trusted"),
        ("kunal.desai@example.com", "Kunal Desai", "user", 42, "trusted"),
        ("sneha.reddy@example.com", "Sneha Reddy", "user", 40, "trusted"),
        ("rohit.sharma@example.com", "Rohit Sharma", "user", 38, "trusted"),
        ("aakash.chopra@example.com", "Aakash Chopra", "user", 36, "trusted"),
        ("bhavna.patel@example.com", "Bhavna Patel", "user", 35, "trusted"),
        ("chirag.mehta@example.com", "Chirag Mehta", "user", 34, "trusted"),
        ("disha.vakil@example.com", "Disha Vakil", "user", 32, "trusted"),
        ("esha.deol@example.com", "Esha Deol", "user", 30, "trusted"),
    ]

    # Additional user generators to reach 108 total users
    first_names = [
        "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan", "Krishna", "Ishaan",
        "Shaurya", "Atharv", "Aarush", "Advik", "Kabir", "Dhruv", "Rudra", "Aryan", "Ananya", "Diya",
        "Aadhya", "Pari", "Saanvi", "Myra", "Sara", "Isha", "Rhea", "Tara", "Kiara", "Kavya",
        "Prisha", "Avni", "Ahana", "Navya", "Riddhima", "Shanaya", "Trisha", "Anika", "Samyak", "Tanishq",
        "Yash", "Varun", "Abhimanyu", "Kartik", "Karan", "Prateek", "Mohit", "Naveen", "Raghav", "Sameer",
        "Sunil", "Vikas", "Vinay", "Ashok", "Girish", "Manoj", "Pramod", "Ramesh", "Suresh", "Vijay",
        "Rekha", "Shobha", "Usha", "Suman", "Geeta", "Sunita", "Seema", "Shalini", "Kusum", "Pushpa"
    ]
    last_names = [
        "Agarwal", "Bansal", "Chauhan", "Dutta", "Garg", "Hegde", "Jadhav", "Khatri", "Lal", "Majumdar",
        "Nanda", "Ojha", "Pillai", "Qureshi", "Rathore", "Saxena", "Talwar", "Upadhyay", "Vohra", "Yadav"
    ]

    extra_users = []
    idx = 0
    for fn in first_names:
        ln = last_names[idx % len(last_names)]
        email = f"{fn.lower()}.{ln.lower()}{idx+1}@example.com"
        name = f"{fn} {ln}"
        rep = (idx * 3) % 29  # 0 to 28
        tier = "new" if rep >= 20 else "newcomer"
        extra_users.append((email, name, "user", rep, tier))
        idx += 1
        if len(demo_users) + len(extra_users) >= 108:
            break

    all_users_meta = demo_users + extra_users
    user_map = {}  # email -> uuid_str

    for email, name, role, rep, tier in all_users_meta:
        u_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO users (id, email, name, password, role, emailVerified, is_active, "
            "reputation_score, reputation_tier, total_reports, verified_reports, total_votes_cast, accurate_votes) "
            "VALUES (UUID_TO_BIN(%s), %s, %s, %s, %s, TRUE, TRUE, %s, %s, %s, %s, %s, %s)",
            (u_id, email, name, HASHED_PASSWORD, role, rep, tier, 2 if rep > 30 else 0, 1 if rep > 40 else 0, rep // 2, rep // 3),
        )
        user_map[email] = u_id

    conn.commit()
    print(f"  Inserted {len(all_users_meta)} users.")

    # 3. Retrieve Categories & Tags
    cur.execute("SELECT BIN_TO_UUID(id) AS id, slug, name FROM categories")
    cat_rows = cur.fetchall()
    cat_map = {c["slug"]: c["id"] for c in cat_rows}

    cur.execute("SELECT BIN_TO_UUID(id) AS id, slug, name FROM tags")
    tag_rows = cur.fetchall()
    tag_map = {t["slug"]: t["id"] for t in tag_rows}

    # 4. Define 20 Realistic Reports & Evidence
    print("Seeding 20 realistic fraud reports and generating authentic evidence graphics...")

    scam_reports = [
        {
            "domain": "sbi-yono-kycupdate.xyz",
            "cat_slug": "phishing",
            "title": "SBI YONO NetBanking KYC Expiry Phishing Portal",
            "desc": "Received an SMS with high urgency claiming my SBI YONO NetBanking account would be frozen within 24 hours if KYC was not updated. The link redirected to a pixel-perfect clone of the SBI NetBanking login page requesting CIF username, password, and transaction PIN. Within 5 minutes of input, ₹85,000 was debited via IMPS.",
            "brand": "State Bank of India",
            "amount": 85000.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 96.50,
            "risk_level": "critical",
            "tags": ["credential-theft", "upi-fraud"],
            "reporter": "rohit.sharma@example.com",
            "evidence_type": "phishing_portal",
        },
        {
            "domain": "mahadiscom-billpay.in",
            "cat_slug": "payment-fraud",
            "title": "Electricity Bill Cutoff Urgency SMS & Fake Payment APK",
            "desc": "Fraudulent SMS received stating: 'Dear Customer, your electricity power will be disconnected at 9:30 PM tonight from electricity office as previous month bill was not updated.' Called the number provided; the caller instructed me to download a 'quick bill verify' app and pay ₹10. The APK intercepted SMS OTPs and debited ₹14,500.",
            "brand": "Mahadiscom",
            "amount": 14500.00,
            "stage": "confirmed_malicious",
            "status": "active",
            "risk_score": 98.00,
            "risk_level": "critical",
            "tags": ["upi-fraud"],
            "reporter": "sanjay.verma@example.com",
            "evidence_type": "sms",
        },
        {
            "domain": "flipkart-diwali-dhamaka.shop",
            "cat_slug": "fake-ecommerce",
            "title": "Fake Flipkart Diwali Flash Sale - iPhone 15 for ₹14,999",
            "desc": "Encountered a sponsored advertisement on Facebook advertising an unprecedented Diwali clearance sale for Apple iPhone 15 at ₹14,999. The site perfectly copied Flipkart's CSS, logo, and checkout flow. Payment was restricted strictly to UPI QR code scanning. After paying ₹14,999, the order status disappeared and helpline numbers went unreachable.",
            "brand": "Flipkart",
            "amount": 14999.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 88.50,
            "risk_level": "critical",
            "tags": ["upi-fraud"],
            "reporter": "aakash.chopra@example.com",
            "evidence_type": "ecommerce_deal",
        },
        {
            "domain": "telegram-youtube-tasks.site",
            "cat_slug": "fake-job-scam",
            "title": "Part-Time YouTube Video Liking & Review Telegram Task Scam",
            "desc": "Contacted via WhatsApp by an individual claiming to be an HR coordinator for digital marketing ratings. Initially earned ₹150 and ₹300 for liking 3 YouTube videos. Then moved into a Telegram group for 'Prepaid High-Return Tasks'. Deposited ₹15,000 for VIP task 2, but the portal showed error and demanded ₹45,000 more to unlock withdrawal. Lost ₹62,000 total.",
            "brand": "Telegram",
            "amount": 62000.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 92.00,
            "risk_level": "critical",
            "tags": ["job-fraud"],
            "reporter": "bhavna.patel@example.com",
            "evidence_type": "whatsapp",
        },
        {
            "domain": "bharat-crypto-wealth.net",
            "cat_slug": "investment-scam",
            "title": "Fake High-Yield Crypto Arbitrage Bot & WhatsApp Trading Group",
            "desc": "Invited into a WhatsApp trading community named 'SEBI Institutional Elite Wealth'. The administrator shared manipulated screenshots showing 40% daily profit. Invested ₹50,000 initially, which supposedly doubled on their custom trading dashboard. When attempting withdrawal of ₹2,40,000, they demanded a 28% 'GST tax deposit'.",
            "brand": "WhatsApp",
            "amount": 240000.00,
            "stage": "confirmed_malicious",
            "status": "active",
            "risk_score": 95.00,
            "risk_level": "critical",
            "tags": ["crypto-scam"],
            "reporter": "chirag.mehta@example.com",
            "evidence_type": "upi_receipt",
        },
        {
            "domain": "indiapost-tracking-delivery.info",
            "cat_slug": "impersonation",
            "title": "India Post Failed Parcel Delivery SMS & Address Update Scam",
            "desc": "Received SMS: '[India Post] Your package could not be delivered due to incomplete street address. Please update your details within 12 hours at indiapost-tracking-delivery.info to prevent return.' Site asked for address and a ₹25 re-delivery processing charge. Card credentials entered were used for fraudulent POS transactions.",
            "brand": "India Post",
            "amount": 25.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 91.00,
            "risk_level": "critical",
            "tags": ["credential-theft"],
            "reporter": "disha.vakil@example.com",
            "evidence_type": "sms",
        },
        {
            "domain": "epfo-claim-status.apk-download.net",
            "cat_slug": "malware",
            "title": "Fake EPFO Pension Passbook Android APK with SMS Stealer",
            "desc": "Site claims to provide direct EPFO PF passbook download without UAN login. The downloaded file 'EPFO_Passbook_v3.2.apk' is a trojan that requests SMS and accessibility permissions, forwarding all 2FA OTPs to an offshore command-and-control server in Moscow.",
            "brand": "EPFO",
            "amount": 35000.00,
            "stage": "multiple_reports",
            "status": "active",
            "risk_score": 85.00,
            "risk_level": "critical",
            "tags": ["credential-theft"],
            "reporter": "esha.deol@example.com",
            "evidence_type": "phishing_portal",
        },
        {
            "domain": "olx-buyer-qr-pay.site",
            "cat_slug": "payment-fraud",
            "title": "OLX Army Officer QR Code Scan 'Receive Money' Reverse Payment Scam",
            "desc": "Listed a sofa on OLX. Buyer claimed to be an Indian Army official stationed at Pune cantt. Said he will pay via PhonePe QR code. Sent a QR code stating 'Scan to receive advance ₹10,000'. Upon scanning and entering UPI PIN, ₹10,000 was debited instead of credited. When questioned, scammer claimed glitch and did another ₹18,000 reverse debit.",
            "brand": "OLX",
            "amount": 28000.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 89.00,
            "risk_level": "critical",
            "tags": ["upi-fraud"],
            "reporter": "neha.gupta@example.com",
            "evidence_type": "upi_receipt",
        },
        {
            "domain": "hdfc-netbanking-rewardpoints.co",
            "cat_slug": "phishing",
            "title": "HDFC Credit Card Reward Points Expiry Redemption Phishing",
            "desc": "SMS notification claiming: 'Dear HDFC customer, your 8,450 reward points worth ₹4,225 are expiring today. Redeem cash now at hdfc-netbanking-rewardpoints.co'. Fake portal requested 16-digit card number, expiry, CVV, and netbanking password.",
            "brand": "HDFC Bank",
            "amount": 42300.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 94.00,
            "risk_level": "critical",
            "tags": ["credential-theft", "credit-card"],
            "reporter": "amit.kumar@example.com",
            "evidence_type": "phishing_portal",
        },
        {
            "domain": "shoes-wholesale-surat.store",
            "cat_slug": "product-never-delivered",
            "title": "Instagram Sponsored Ad Branded Sneaker Sale - Defunct Gateway",
            "desc": "Ordered two pairs of Nike Air Jordan sneakers advertised on an Instagram story ad for ₹3,499. Received fake order tracking number with no carrier listed. Support email bounced and Instagram handle was deleted 4 days later.",
            "brand": "Instagram",
            "amount": 3499.00,
            "stage": "under_review",
            "status": "active",
            "risk_score": 68.00,
            "risk_level": "high",
            "tags": ["upi-fraud"],
            "reporter": "deepa.nair@example.com",
            "evidence_type": "ecommerce_deal",
        },
        {
            "domain": "airport-groundstaff-jobs.org",
            "cat_slug": "fake-job-scam",
            "title": "Indigo Airlines Airport Ground Staff Recruitment Deposit Scam",
            "desc": "Received fake recruitment offer letter with IndiGo logo offering airport ground staff position in Delhi T3 terminal at ₹32,000/month. Asked to pay ₹4,500 for medical test and ₹14,000 for uniform security deposit before joining.",
            "brand": "IndiGo Airlines",
            "amount": 18500.00,
            "stage": "multiple_reports",
            "status": "active",
            "risk_score": 79.00,
            "risk_level": "high",
            "tags": ["job-fraud"],
            "reporter": "kunal.desai@example.com",
            "evidence_type": "whatsapp",
        },
        {
            "domain": "trai-sim-deactivation.net",
            "cat_slug": "impersonation",
            "title": "Fake TRAI / Mumbai Police 2-Hour SIM Card Block Threat",
            "desc": "Automated IVR call stating: 'This call is from Telecom Regulatory Authority of India. Your mobile number has been found in 17 illegal harassment cases and will be deactivated in 2 hours.' Transferred to fake police officer demanding video verification and asset disclosure.",
            "brand": "TRAI",
            "amount": 115000.00,
            "stage": "confirmed_malicious",
            "status": "active",
            "risk_score": 97.00,
            "risk_level": "critical",
            "tags": ["upi-fraud"],
            "reporter": "sneha.reddy@example.com",
            "evidence_type": "sms",
        },
        {
            "domain": "instant-pan-loan-approval.xyz",
            "cat_slug": "suspicious-behaviour",
            "title": "Instant 5-Minute Paperless Personal Loan App Demanding Contacts Access",
            "desc": "Loan app offering ₹50,000 instant loan with zero CIBIL check. Before approving, app uploads entire contact book and photo gallery to private server, then disburses only ₹2,800 and demands ₹6,000 within 6 days while threatening contact blackmail.",
            "brand": "Bajaj Finserv",
            "amount": 5000.00,
            "stage": "reported",
            "status": "active",
            "risk_score": 62.00,
            "risk_level": "high",
            "tags": ["credential-theft"],
            "reporter": "rohit.sharma@example.com",
            "evidence_type": "sms",
        },
        {
            "domain": "zara-clearance-sale.online",
            "cat_slug": "fake-ecommerce",
            "title": "Counterfeit Zara Clothing Clearance Website with Fake Reviews",
            "desc": "Exact replica of Zara India online store advertising end-of-season dresses and coats at 90% discount. Accepts credit card and UPI payments. Dispatches either empty envelopes or cheap cloth rags from a dummy Surat address.",
            "brand": "Zara",
            "amount": 4890.00,
            "stage": "under_review",
            "status": "active",
            "risk_score": 71.00,
            "risk_level": "high",
            "tags": ["credit-card"],
            "reporter": "bhavna.patel@example.com",
            "evidence_type": "ecommerce_deal",
        },
        {
            "domain": "sharekhan-vip-calls.com",
            "cat_slug": "investment-scam",
            "title": "Fake SEBI Registered Stock Advisory Tip Telegram Channel",
            "desc": "Impersonated Sharekhan brokerage house offering guaranteed 100% intraday call options. Charged ₹25,000 VIP subscription, followed by recommending illiquid penny stocks in a pump-and-dump scheme. Lost ₹1,50,000 capital.",
            "brand": "Sharekhan",
            "amount": 150000.00,
            "stage": "multiple_reports",
            "status": "active",
            "risk_score": 83.00,
            "risk_level": "critical",
            "tags": ["crypto-scam"],
            "reporter": "chirag.mehta@example.com",
            "evidence_type": "whatsapp",
        },
        {
            "domain": "remote-anydesk-support-helpline.click",
            "cat_slug": "malware",
            "title": "Customer Care Google Ad Impersonation Demanding AnyDesk/TeamViewer",
            "desc": "Searched Google for Swiggy refund customer care. Found sponsored number 1800-XXX-XXXX leading to this landing page. Agent asked to download AnyDesk 'for screen-sharing refund token'. Remotely initiated ₹78,000 NetBanking fund transfer while hiding screen.",
            "brand": "AnyDesk",
            "amount": 78000.00,
            "stage": "community_verified",
            "status": "active",
            "risk_score": 93.00,
            "risk_level": "critical",
            "tags": ["credential-theft", "upi-fraud"],
            "reporter": "disha.vakil@example.com",
            "evidence_type": "phishing_portal",
        },
        {
            "domain": "challan-parivahan-pay.link",
            "cat_slug": "payment-fraud",
            "title": "Traffic Police E-Challan Overdue Fine Notification SMS",
            "desc": "Received text: 'Vehicle MH-12-XX-4920 has 1 unpaid speed violation notice. Pay ₹1000 now on challan-parivahan-pay.link or court warrant will be generated.' Payment gateway on site was a phishing clone capturing debit card details.",
            "brand": "Parivahan Sewa",
            "amount": 1000.00,
            "stage": "multiple_reports",
            "status": "active",
            "risk_score": 75.00,
            "risk_level": "high",
            "tags": ["upi-fraud"],
            "reporter": "esha.deol@example.com",
            "evidence_type": "sms",
        },
        {
            "domain": "netflix-subscription-renew.top",
            "cat_slug": "phishing",
            "title": "Netflix Subscription Suspended Account Verification Phishing",
            "desc": "Email stating: 'Your Netflix membership is on hold because your monthly billing card was declined. Update billing to avoid cancellation.' Phishing form steals card number and CVV.",
            "brand": "Netflix",
            "amount": 649.00,
            "stage": "reported",
            "status": "active",
            "risk_score": 64.00,
            "risk_level": "high",
            "tags": ["credit-card"],
            "reporter": "amit.kumar@example.com",
            "evidence_type": "phishing_portal",
        },
        {
            "domain": "courier-fedex-customs-clearance.cc",
            "cat_slug": "impersonation",
            "title": "FedEx Illegal Drugs in Parcel Threat by Fake CBI Officer",
            "desc": "Target was called by scammers impersonating FedEx customer support claiming a parcel containing 5 passports and 140 grams of MDMA drugs addressed to them was intercepted in Mumbai customs. Transferred to fake CBI official on Skype who coerced ₹3,20,000 into a 'RBI Verification Escrow Account'.",
            "brand": "FedEx",
            "amount": 320000.00,
            "stage": "confirmed_malicious",
            "status": "active",
            "risk_score": 99.00,
            "risk_level": "critical",
            "tags": ["upi-fraud"],
            "reporter": "sanjay.verma@example.com",
            "evidence_type": "upi_receipt",
        },
        {
            "domain": "tourist-visa-schengen-fasttrack.agency",
            "cat_slug": "other",
            "title": "Guaranteed Schengen Visa Appointment Bot Demanding Advance USDT",
            "desc": "Operates a fake VFS appointment slot booking bot claiming exclusive premium embassy slots for Germany and France. Charges ₹45,000 in cryptocurrency advance. Zero appointments booked, domain WHOIS is anonymized in Iceland.",
            "brand": "VFS Global",
            "amount": 45000.00,
            "stage": "under_review",
            "status": "active",
            "risk_score": 72.00,
            "risk_level": "high",
            "tags": ["crypto-scam"],
            "reporter": "deepa.nair@example.com",
            "evidence_type": "whatsapp",
        },
    ]

    # Pre-select trusted voters (rep >= 60)
    trusted_voters = [
        user_map["vikram.hunter@scamalert.in"],
        user_map["rahul.patel@scamalert.in"],
        user_map["aditi.rao@scamalert.in"],
        user_map["siddharth.nair@scamalert.in"],
        user_map["divya.menon@scamalert.in"],
        user_map["rohan.malhotra@scamalert.in"],
        user_map["moderator@scamalert.in"],
        user_map["priya.sharma@cybercell.gov.in"],
    ]

    report_count = 0
    for s in scam_reports:
        # Create website_urls row
        w_id = str(uuid.uuid4())
        norm_url = f"https://{s['domain']}"
        cur.execute(
            "INSERT INTO website_urls (id, normalized_url, raw_url, domain, ssl_valid, dmarc_exists, spf_exists, "
            "blacklist_matches, risk_score, risk_level, total_reports, confirmed_reports, active_reports) "
            "VALUES (UUID_TO_BIN(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, 1)",
            (w_id, norm_url, norm_url, s["domain"], False if s["risk_score"] > 85 else True, False, False, 5 if s["risk_score"] > 80 else 1, s["risk_score"], s["risk_level"]),
        )

        # Create fraud_reports row
        r_id = str(uuid.uuid4())
        reporter_id = user_map.get(s["reporter"], user_map["neha.gupta@example.com"])
        cat_id = cat_map.get(s["cat_slug"])
        confirm_votes = 6 if s["stage"] in ("community_verified", "confirmed_malicious") else (3 if s["stage"] == "multiple_reports" else 1)
        total_votes = confirm_votes

        cur.execute(
            "INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description, "
            "target_brand, amount_lost, currency, country_code, status, verification_stage, is_anonymous, "
            "confirm_votes, deny_votes, total_votes, created_at) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s, %s, 'INR', 'IN', "
            "%s, %s, FALSE, %s, 0, %s, NOW())",
            (r_id, reporter_id, w_id, cat_id, s["title"], s["desc"], s["brand"], s["amount"], s["status"], s["stage"], confirm_votes, total_votes),
        )

        # Link Tags
        for tslug in s["tags"]:
            tid = tag_map.get(tslug)
            if tid:
                cur.execute(
                    "INSERT IGNORE INTO report_tags (report_id, tag_id) VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s))",
                    (r_id, tid),
                )

        # Generate & Store Evidence Image on Disk
        report_upload_dir = os.path.join(EVIDENCE_DIR, r_id)
        os.makedirs(report_upload_dir, exist_ok=True)
        evidence_filename = f"evidence_{s['evidence_type']}.png"
        evidence_path = os.path.join(report_upload_dir, evidence_filename)

        if s["evidence_type"] == "sms":
            create_sms_evidence(sender="VK-MSDCL" if "Electricity" in s["title"] else "AD-INDPOST", message=s["desc"][:180], dest_path=evidence_path)
        elif s["evidence_type"] == "phishing_portal":
            create_browser_phishing_evidence(domain=s["domain"], brand=s["brand"].upper(), alert_text=s["title"], dest_path=evidence_path)
        elif s["evidence_type"] == "upi_receipt":
            create_upi_receipt_evidence(amount=f"{s['amount']:,.2f}", recipient="cyber.fraud@axl", dest_path=evidence_path)
        elif s["evidence_type"] == "whatsapp":
            create_whatsapp_chat_evidence(contact=f"{s['brand']} Customer Care", dest_path=evidence_path)
        elif s["evidence_type"] == "ecommerce_deal":
            create_ecommerce_deal_evidence(product=s["title"], deal_price=f"₹{int(s['amount']):,}", dest_path=evidence_path)
        else:
            create_sms_evidence(sender="ALERT", message=s["desc"][:160], dest_path=evidence_path)

        # Register in report_evidence table
        with open(evidence_path, "rb") as ef:
            content = ef.read()
            file_hash = hashlib.sha256(content).hexdigest()
            file_size = len(content)

        ev_id = str(uuid.uuid4())
        public_file_path = f"/uploads/evidence/{r_id}/{evidence_filename}"
        cur.execute(
            "INSERT INTO report_evidence (id, report_id, uploaded_by, evidence_type, file_name, file_path, "
            "mime_type, file_size_bytes, sha256_hash, description, is_approved) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), 'screenshot', %s, %s, 'image/png', %s, %s, %s, TRUE)",
            (ev_id, r_id, reporter_id, evidence_filename, public_file_path, file_size, file_hash, f"Direct visual evidence captured for {s['title']}"),
        )

        # Insert Verification Votes from Trusted Hunters
        vote_comments = [
            f"WHOIS check confirms {s['domain']} was registered less than 20 days ago through privacy proxy.",
            f"Technical verification completed: SSL certificate is self-signed/short-lived and infrastructure matches known cybercrime syndicates.",
            f"Confirmed phishing signatures. Similar attacks reported on cybercrime helpline 1930.",
            f"Matches deceptive impersonation pattern targeting {s['brand']}.",
            f"Cross-verified with NCRP reporting logs.",
            f"Domain resolves to suspicious bulletproof hosting IP.",
        ]
        for v_idx in range(confirm_votes):
            voter = trusted_voters[v_idx % len(trusted_voters)]
            v_id = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO verification_votes (id, report_id, voter_id, vote_type, confidence, comment, voter_reputation_at_vote) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), 'confirm', 0.95, %s, 75)",
                (v_id, r_id, voter, vote_comments[v_idx % len(vote_comments)]),
            )

        # Insert Comments
        cur.execute(
            "INSERT INTO report_comments (id, report_id, user_id, body) VALUES "
            "(UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s), "
            "(UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s)",
            (
                r_id, user_map["priya.sharma@cybercell.gov.in"],
                f"Please ensure you file a formal NCRP complaint at https://cybercrime.gov.in or call 1930 with transaction reference.",
                r_id, user_map["rahul.patel@scamalert.in"],
                f"Takedown request sent to the registrar for {s['domain']}. Users be aware of similar domains.",
            ),
        )

        # Insert History Entries
        cur.execute(
            "INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value) VALUES "
            "(UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), 'created', NULL, '{\"stage\":\"reported\"}'), "
            "(UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), 'status_changed', '{\"stage\":\"reported\"}', %s)",
            (r_id, reporter_id, r_id, user_map["admin@scamalert.in"], f'{{"stage":"{s["stage"]}"}}'),
        )

        # Insert Risk Score Breakdown
        cur.execute(
            "INSERT INTO risk_score_breakdowns (id, website_url_id, community_sub_score, automated_sub_score, category_severity_avg, final_score, signals) "
            "VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), %s, %s, 8.50, %s, '{\"verified\": true, \"dns_sec\": false}')",
            (w_id, s["risk_score"] - 2, s["risk_score"] + 1, s["risk_score"]),
        )

        report_count += 1

    # 5. Insert Website Forum Discussions
    print("Seeding website discussion threads...")
    featured_wids = []
    cur.execute("SELECT BIN_TO_UUID(id) AS id, domain FROM website_urls LIMIT 5")
    for w_row in cur.fetchall():
        cur.execute(
            "INSERT INTO website_discussions (id, website_url_id, author_id, title, body, upvotes, reply_count) "
            "VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, 8, 2)",
            (
                w_row["id"], user_map["vikram.hunter@scamalert.in"],
                f"Technical Analysis and Infrastructure Breakdown for {w_row['domain']}",
                f"We analyzed the DNS records, hosting ASNs, and payment gateways associated with {w_row['domain']}. It belongs to an active credential-harvesting cluster. Stay alert.",
            )
        )

    conn.commit()
    cur.close()
    conn.close()

    print(f"\n[OK] Showcase database seeding complete!")
    print(f"  * Users seeded: {len(all_users_meta)} (All accounts password: '{UNIVERSAL_PASSWORD}')")
    print(f"  * Fraud Reports seeded: {report_count}")
    print(f"  * Generated evidence images: {report_count} (Saved in {EVIDENCE_DIR})")


if __name__ == "__main__":
    seed_database()
