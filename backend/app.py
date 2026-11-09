
import os
import hashlib
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from sqlalchemy import URL, text
from dotenv import load_dotenv
from uuid import uuid4
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

database_url = URL.create(
    drivername="postgresql+psycopg",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", "5432")),
    database=os.getenv("DB_NAME")
)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

app.config["UPLOAD_FOLDER"] = os.path.join(
    app.instance_path,
    "private_documents"
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

password_hasher = PasswordHasher()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="owner")
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        db.CheckConstraint(
            "role IN ('admin', 'owner', 'viewer')",
            name="check_user_role"
        ),
    )

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(255), unique=True, nullable=False)
    category = db.Column(db.String(100), nullable=True)

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class DocumentPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id", ondelete="CASCADE"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False
    )

    permission = db.Column(db.String(10), nullable=False)

    granted_by_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_permission"
        ),
        db.CheckConstraint(
            "permission IN ('read', 'edit')",
            name="check_document_permission"
        ),
    )
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(60), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    previous_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)

def has_document_access(document, action="read"):
    if current_user.role == "admin":
        return True

    if document.owner_id == current_user.id:
        return True

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    if permission is None:
        return False

    if action == "read":
        return permission.permission in ("read", "edit")

    if action == "edit":
        return permission.permission == "edit"

    return False
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "png", "jpg", "jpeg", "xlsx", "csv"
}
def record_audit(action, document_id=None, details=None):
    last_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()

    previous_hash = last_entry.entry_hash if last_entry else "0" * 64
    created_at = datetime.now(timezone.utc)

    actor_id = (
        current_user.id
        if current_user.is_authenticated
        else None
    )

    payload = (
        f"{previous_hash}|{actor_id}|{action}|"
        f"{document_id}|{details or ''}|{created_at.isoformat()}"
    )

    entry_hash = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    audit_entry = AuditLog(
        actor_id=actor_id,
        action=action,
        document_id=document_id,
        details=details,
        created_at=created_at,
        previous_hash=previous_hash,
        entry_hash=entry_hash
    )

    db.session.add(audit_entry)

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )
@app.route("/documents/<int:document_id>/download", methods=["GET"])
@login_required
def download_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    if not has_document_access(document, "read"):
        return jsonify({"error": "Access denied"}), 403

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.storage_key
    )

    if not os.path.isfile(file_path):
        return jsonify({"error": "File not found"}), 404
    record_audit(
        "DOCUMENT_DOWNLOAD",
        document.id,
        f"Downloaded file: {document.original_filename}"
    )

    db.session.commit()
    return send_file(
        file_path,
        as_attachment=True,
        download_name=document.original_filename
    )
@app.route("/documents/<int:document_id>/permissions", methods=["POST"])
@login_required
def grant_document_permission(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    if current_user.role != "admin" and document.owner_id != current_user.id:
        return jsonify({"error": "Only the owner or admin can share"}), 403

    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    permission_type = data.get("permission", "").strip().lower()

    if not email or permission_type not in ("read", "edit"):
        return jsonify({
            "error": "Valid email and permission are required"
        }), 400

    target_user = User.query.filter_by(email=email).first()

    if target_user is None:
        return jsonify({"error": "User not found"}), 404

    if target_user.id == document.owner_id:
        return jsonify({
            "error": "Owner already has full access"
        }), 400

    existing_permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=target_user.id
    ).first()

    try:
        if existing_permission:
            existing_permission.permission = permission_type
            existing_permission.granted_by_id = current_user.id
        else:
            new_permission = DocumentPermission(
                document_id=document.id,
                user_id=target_user.id,
                permission=permission_type,
                granted_by_id=current_user.id
            )

            db.session.add(new_permission)
            
        record_audit(
            "PERMISSION_GRANTED",
            document.id,
            f"Granted {permission_type} access to {target_user.email}"
        )

        db.session.commit()

        return jsonify({
            "message": "Document permission granted successfully",
            "user": target_user.email,
            "permission": permission_type
        }), 200
    except Exception:
        db.session.rollback()
        app.logger.exception("Permission grant failed")
        return jsonify({"error": "Permission grant failed"}), 500

@app.route("/documents/<int:document_id>/permissions/<int:user_id>", methods=["DELETE"])
@login_required
def revoke_document_permission(document_id, user_id):
    document = db.session.get(Document, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    if current_user.role != "admin" and document.owner_id != current_user.id:
        return jsonify({"error": "Only the owner or admin can revoke access"}), 403

    permission = DocumentPermission.query.filter_by(
        document_id=document_id,
        user_id=user_id
    ).first()

    if permission is None:
        return jsonify({"error": "Permission not found"}), 404

    try:
        revoked_user = db.session.get(User, user_id)

        record_audit(
            "PERMISSION_REVOKED",
            document.id,
            f"Revoked access from {revoked_user.email if revoked_user else user_id}"
        )

        db.session.delete(permission)
        db.session.commit()

        return jsonify({
            "message": "Document access revoked successfully"
        }), 200

    except Exception:
        db.session.rollback()
        app.logger.exception("Permission revocation failed")
        return jsonify({"error": "Permission revocation failed"}), 500
@app.route("/documents/<int:document_id>", methods=["PATCH"])
@login_required
def edit_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    if not has_document_access(document, "edit"):
        return jsonify({"error": "Edit access denied"}), 403

    data = request.get_json(silent=True) or {}

    title = data.get("title", document.title)
    category = data.get("category", document.category or "")

    if not isinstance(title, str) or not isinstance(category, str):
        return jsonify({"error": "Invalid title or category"}), 400

    title = title.strip()
    category = category.strip()

    if not title:
        return jsonify({"error": "Title is required"}), 400

    if len(title) > 200 or len(category) > 100:
        return jsonify({"error": "Title or category is too long"}), 400

    try:
        document.title = title
        document.category = category or None

        db.session.commit()

        return jsonify({
            "message": "Document updated successfully",
            "document": {
                "id": document.id,
                "title": document.title,
                "category": document.category
            }
        }), 200

    except Exception:
        db.session.rollback()
        app.logger.exception("Document update failed")
        return jsonify({"error": "Document update failed"}), 500
@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "Please select a file"}), 400

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename or not allowed_file(original_filename):
        return jsonify({"error": "File type not allowed"}), 400

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()

    if not title:
        return jsonify({"error": "Document title is required"}), 400

    if len(title) > 200 or len(category) > 100:
        return jsonify({"error": "Title or category is too long"}), 400

    extension = original_filename.rsplit(".", 1)[1].lower()
    storage_key = f"{uuid4().hex}.{extension}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        storage_key
    )

    try:
        uploaded_file.save(file_path)

        document = Document(
            title=title,
            original_filename=original_filename,
            storage_key=storage_key,
            category=category or None,
            owner_id=current_user.id
        )

        db.session.add(document)
        db.session.flush()

        record_audit(
            "DOCUMENT_UPLOAD",
            document.id,
            f"Uploaded file: {original_filename}"
        )

        db.session.commit()
        return jsonify({
            "message": "Document uploaded successfully",
            "document": {
                "id": document.id,
                "title": document.title,
                "filename": document.original_filename,
                "category": document.category,
                "owner_id": document.owner_id
            }
        }), 201

    except Exception:
        db.session.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        app.logger.exception("Document upload failed")
        return jsonify({"error": "Document upload failed"}), 500
    

@app.route("/documents/<int:document_id>", methods=["DELETE"])
@login_required
def delete_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    # Only the owner or admin can delete
    if current_user.role != "admin" and document.owner_id != current_user.id:
        return jsonify({"error": "Only the owner or admin can delete this document"}), 403

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.storage_key
    )

    try:
        # Remove associated permissions
        DocumentPermission.query.filter_by(
            document_id=document.id
        ).delete(synchronize_session=False)

        # Delete document record
        db.session.delete(document)
        db.session.commit()

        # Remove stored file
        if os.path.exists(file_path):
            os.remove(file_path)

        return jsonify({
            "message": "Document deleted successfully"
        }), 200

    except Exception:
        db.session.rollback()
        app.logger.exception("Document deletion failed")
        return jsonify({"error": "Document deletion failed"}), 500

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if len(password) < 12:
        return jsonify({
            "error": "Password must be at least 12 characters"
        }), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"error": "Email already registered"}), 409

    try:
        new_user = User(
            name=name,
            email=email,
            password_hash=password_hasher.hash(password),
            role="owner"
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "Registration successful",
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "role": new_user.role
            }
        }), 201

    except Exception:
        db.session.rollback()
        app.logger.exception("Registration failed")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/documents", methods=["GET"])
@login_required
def list_documents():

    if current_user.role == "admin":
        documents = Document.query.all()

    else:
        owned_documents = Document.query.filter_by(
            owner_id=current_user.id
        ).all()

        shared_permissions = DocumentPermission.query.filter_by(
            user_id=current_user.id
        ).all()

        shared_document_ids = [
            permission.document_id
            for permission in shared_permissions
        ]

        shared_documents = Document.query.filter(
            Document.id.in_(shared_document_ids)
        ).all()

        # Remove duplicate documents
        document_map = {
            document.id: document
            for document in owned_documents + shared_documents
        }

        documents = list(document_map.values())

    # Search by title, filename or category
    search_text = request.args.get("q", "").strip().lower()
    category_filter = request.args.get("category", "").strip().lower()

    if search_text:
        documents = [
            doc for doc in documents
            if search_text in doc.title.lower()
            or search_text in doc.original_filename.lower()
            or search_text in (doc.category or "").lower()
        ]

    if category_filter:
        documents = [
            doc for doc in documents
            if category_filter in (doc.category or "").lower()
        ]

    return jsonify({
        "documents": [
            {
                "id": document.id,
                "title": document.title,
                "filename": document.original_filename,
                "category": document.category,
                "owner_id": document.owner_id,
                "created_at": document.created_at.isoformat()
            }
            for document in documents
        ]
    }), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    try:
        password_hasher.verify(user.password_hash, password)

    except (VerifyMismatchError, InvalidHashError):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    login_user(user)

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }), 200
@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({
        "error": "Please login first"
    }), 401


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return jsonify({
        "message": "Welcome to TrustVault Dashboard",
        "user": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "role": current_user.role
        }
    }), 200
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()

    return jsonify({
        "message": "Logout successful"
    }), 200
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/db-check")
def db_check():
    try:
        with db.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return jsonify({"database": "Connected successfully!"})
    except Exception:
        app.logger.exception("Database connection failed")
        return jsonify({"database": "Connection failed"}), 500


if __name__ == "__main__":
    app.run(debug=True)
