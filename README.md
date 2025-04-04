# 🔐 CryptWallet – Secure Encrypted File Storage System

CryptWallet is a secure and simple web-based vault system where users can upload, download, and manage their files privately. Built using Django and Python, with an emphasis on privacy and clean UI.

Requirements

- Python 3.x
- Django 4.x
- HTML/CSS + Bootstrap for frontend
- SQLite (or any other database you prefer)
- `cryptography` library for encryption

Installation Steps

1. Clone the Repository

git clone https://github.com/yourusername/cryptwallet.git
cd cryptwallet

2. Set Up Virtual Environment

python -m venv venv
# Activate the virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

3. Install Dependencies

pip install -r requirements.txt

4. Set Up the Database

python manage.py makemigrations
python manage.py migrate

5. Create a Superuser (Admin)

python manage.py createsuperuser

Follow the prompts to create your admin account.

6. Run the Server

python manage.py runserver

Visit http://localhost:8000 in your browser to access the app.

⸻


Login / Register
	•	Open the home page: http://localhost:8000
	•	Register a new account or login with an existing one.

Uploading Files
	•	Head to your Dashboard
	•	Click Upload File
	•	The file is automatically encrypted before saving!

Managing Files
	•	View a list of your uploaded (encrypted) files
	•	You can:
	•	✅ Download (Decrypted on the fly)
	•	🗑️ Delete

⸻

🛡️ How It Works (Encryption Logic)
	•	When a file is uploaded:
	•	It’s encrypted using the key
	•	The encrypted file is stored in the media/ folder
	•	When downloaded:
	•	It is decrypted only for the owner
	•	Admins or other users cannot access/decrypt your files

Safety first, always.

⸻

⚠️ Limitations & Rules
	•	File size currently limited by Django default (can be changed).
	•	Only the uploader can see/download/delete their own files.
	•	Encryption is symmetric (Fernet) — simple, secure, and efficient.

⸻

🧬 Username Format (Optional Constraint Example)

You can implement a format like this (if needed):

Start -> Two Digits -> Three Letters -> Four/Five Digits
Regex: ^\d{2}[a-zA-Z]{3}\d{4,5}$




⸻

🔧 Troubleshooting

❌ Application Not Running?
	•	Did you activate your virtual environment?
	•	Did you install the dependencies using pip install -r requirements.txt?
	•	Any typo while running python manage.py runserver?

❌ Can’t Upload Files?
	•	Check if the media/ folder exists and has write permissions.
	•	Ensure the file size is within allowed Django limits.

❌ Database Errors?
	•	Make sure you ran migrations: python manage.py migrate
	•	Check settings.py for any misconfigured database settings.

⸻

📌 Conclusion

This is a basic yet strong foundation for a secure encrypted file storage system. Feel free to mess around and expand on it!

