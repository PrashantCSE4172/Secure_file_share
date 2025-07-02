# 🔐 Secure File Share - FastAPI

A secure file-sharing backend built using FastAPI and SQLite. Supports two user roles:
- **Ops**: Can upload `.docx`, `.pptx`, and `.xlsx` files.
- **Client**: Can view files and generate secure download links.

---

## 🚀 Features

- JWT-based authentication
- File upload with validation
- Tokenized, secure downloads
- Role-based access control
- SQLite database (via SQLAlchemy)

---

## 📦 Installation

```bash
git clone <your-repo-url>
cd <your-project-directory>
pip install -r requirements.txt
