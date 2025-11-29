# bp.py — Final full app (Railway-friendly)
import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, jsonify, send_file, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, login_user, logout_user, login_required, UserMixin, current_user
)
from werkzeug.utils import secure_filename

# ----------------------------
# App config
# ----------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret123')
# SQLite DB file inside app directory by default — works on Railway (ephemeral) and locally.
db_path = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(app.root_path, 'book_portal.db')}"
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Storage folder configurable via env; fallback to local storage directory.
STORAGE_FOLDER = os.environ.get('BOOKS_FOLDER') or os.path.join(app.root_path, 'storage', 'books')
os.makedirs(STORAGE_FOLDER, exist_ok=True)
app.config["BOOKS_FOLDER"] = STORAGE_FOLDER

ALLOWED_EXT = {'pdf', 'jpg', 'jpeg', 'png'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------
# Models
# ----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)          # login by name
    email = db.Column(db.String(200), unique=True, nullable=True)         # optional but visible to admin
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), default='teacher', nullable=False)    # 'admin' or 'teacher'
    is_approved = db.Column(db.Boolean, default=False)                    # admin must approve
    allow_login = db.Column(db.Boolean, default=False)                    # admin allows login after approval

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    original_name = db.Column(db.String(300), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    levels = db.Column(db.String(50))        # example: "1,3,5"
    colors = db.Column(db.String(50))        # example: "red,green"
    category = db.Column(db.String(50))      # example: "story"
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seen = db.Column(db.Boolean, default=False)

# ----------------------------
# Loader
# ----------------------------
@login_manager.user_loader
def load_user(uid):
    try:
        return User.query.get(int(uid))
    except Exception:
        return None

# ----------------------------
# Ensure DB + admin exist at startup (idempotent)
# ----------------------------
def create_db_and_admin():
    # create tables (no-op if already present)
    db.create_all()

    # ensure at least one admin user exists
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        try:
            admin = User(name='admin', email=None, role='admin', is_approved=True, allow_login=True)
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin'))  # allow override via env
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Created default admin user")
        except Exception:
            # Concurrent deployments might both try to create admin — ignore race errors
            db.session.rollback()

# call once now (safe because called in app context)
with app.app_context():
    create_db_and_admin()

# ----------------------------
# Helpers
# ----------------------------
def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXT

def notify_admin(message):
    try:
        note = Notification(message=message)
        db.session.add(note)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to create notification")

# ----------------------------
# Routes — Auth & Basic
# ----------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

# Register (teacher)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip() or None
        password = request.form.get('password', '')

        if not name or not password:
            flash('Please enter name and password')
            return redirect(url_for('register'))

        if name.lower() == 'admin':
            flash('Cannot register with reserved name "admin".')
            return redirect(url_for('register'))

        if User.query.filter_by(name=name).first():
            flash('Name already taken, choose another.')
            return redirect(url_for('register'))

        if email and User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        u = User(name=name, email=email, role='teacher', is_approved=False, allow_login=False)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        # notify admin of new registration
        notify_admin(f"New teacher registered: {name}. Awaiting approval.")
        flash('Registered. Wait for admin approval.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login (name + password)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(name=name).first()
        if not user:
            flash('Invalid name or password')
            return redirect(url_for('login'))

        # if teacher not approved or not allowed
        if user.role == 'teacher':
            if not user.is_approved:
                # notify admin
                notify_admin(f"Unapproved teacher '{user.name}' attempted login.")
                flash('Your account is not yet approved by admin.')
                return redirect(url_for('login'))
            if not user.allow_login:
                notify_admin(f"Blocked teacher '{user.name}' attempted login.")
                flash('Your login is blocked. Admin has been notified.')
                return redirect(url_for('login'))

        if not user.check_password(password):
            flash('Invalid name or password')
            return redirect(url_for('login'))

        login_user(user)
        flash('Login successful')
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('teacher_dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------------------------
# Admin pages & actions
# ----------------------------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()
    books_query = Book.query.order_by(Book.uploaded_at.desc())
    if search_query:
        books_query = books_query.filter(
            Book.original_name.ilike(f"%{search_query}%")
        )
    books = books_query.all()

    teachers = User.query.filter(User.role == 'teacher').all()
    notes = Notification.query.order_by(Notification.created_at.desc()).all()
    return render_template('admin_dashboard.html', teachers=teachers, books=books, notifications=notes, search_query=search_query)


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
def admin_approve(user_id):
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    u.is_approved = True
    u.allow_login = True
    db.session.commit()
    notify_admin(f"Admin approved teacher '{u.name}'.")
    flash(f"Teacher {u.name} approved")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_allow/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_allow(user_id):
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    u.allow_login = not u.allow_login
    db.session.commit()
    notify_admin(f"Admin toggled allow_login for '{u.name}' -> {u.allow_login}")
    flash(f"Toggled login for {u.name}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete(user_id):
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    if u.role == 'admin':
        flash('Cannot delete admin'); return redirect(url_for('admin_dashboard'))
    db.session.delete(u)
    db.session.commit()
    notify_admin(f"Admin deleted teacher '{u.name}'.")
    flash('Teacher deleted')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_notifications', methods=['POST'])
@login_required
def admin_clear_notifications():
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    Notification.query.delete()
    db.session.commit()
    flash('Notifications cleared')
    return redirect(url_for('admin_dashboard'))

# ----------------------------
# Book upload/view
# ----------------------------
@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_book():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))

    # Get file
    f = request.files.get('file')
    if not f or f.filename == '':
        flash('No file chosen')
        return redirect(request.url)

    if not allowed_file(f.filename):
        flash('File type not allowed')
        return redirect(request.url)

    # Levels (multiple checkboxes)
    levels = request.form.getlist('levels')
    levels_str = ",".join(levels) if levels else "1"

    # Colors (multiple checkboxes)
    colors = request.form.getlist('colors')
    colors_str = ",".join(colors) if colors else ""

    # Category
    category = request.form.get('category', 'Story')

    # Save using a secure unique filename
    safe = secure_filename(f.filename)
    base, ext = os.path.splitext(safe)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    stored = f"{base}_{timestamp}{ext}"

    # Save file
    target_path = os.path.join(app.config['BOOKS_FOLDER'], stored)
    f.save(target_path)

    # Create book entry
    b = Book(
        filename=stored,
        original_name=f.filename,
        levels=levels_str,
        colors=colors_str,
        category=category,
        uploader_id=current_user.id
    )

    # Save to DB
    db.session.add(b)
    db.session.commit()

    flash('Uploaded successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/books')
@login_required
def list_books():
    search_query = request.args.get('search', '').strip()
    books_query = Book.query.order_by(Book.uploaded_at.desc())
    if search_query:
        books_query = books_query.filter(
            Book.original_name.ilike(f"%{search_query}%")
        )
    books = books_query.all()
    return render_template('teacher_books.html', books=books, search_query=search_query)

@app.route('/books/<int:book_id>')
@login_required
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    # detect ext
    ext = book.filename.rsplit('.', 1)[-1].lower()
    is_pdf = (ext == 'pdf')
    return render_template('view_book.html', book=book, is_pdf=is_pdf)

# Serve book to teacher/admin for inline viewing (stream)
@app.route('/books/stream/<int:book_id>')
@login_required
def stream_book(book_id):
    b = Book.query.get_or_404(book_id)

    # Build full path in persistent folder
    path = os.path.join(app.config['BOOKS_FOLDER'], b.filename)

    if not os.path.exists(path):
        abort(404, description="File not found. It may have been deleted.")

    return send_file(
        path,
        as_attachment=False,
        download_name=b.original_name,
        mimetype='application/pdf'
    )


# ----------------------------
# Notification for download/print/screenshot attempts (AJAX POST)
# ----------------------------
@app.route('/notify_attempt', methods=['POST'])
@login_required
def notify_attempt():
    # expects JSON or form with fields: type, book_title (optional)
    typ = None
    book = None

    # prefer JSON if provided
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}

    typ = request.form.get('type') or data.get('type')
    book = request.form.get('book') or data.get('book')
    user = current_user.name if current_user else 'anonymous'
    if typ:
        msg = f"{user} attempted {typ}"
        if book:
            msg += f" on {book}"
        notify_admin(msg)
        return jsonify({'status': 'ok'}), 200
    return jsonify({'status': 'bad request'}), 400

# ----------------------------
# Forgot password (placeholder)
# ----------------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('user_identifier', '').strip()
        # Here you can implement your reset logic (send email etc.)
        flash(f'If an account exists for \"{identifier}\", instructions have been sent.')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

# ----------------------------
# Teacher dashboard
# ----------------------------
@app.route('/teacher')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('Access denied')
        return redirect(url_for('login'))
    return render_template('teacher_dashboard.html')


@app.route('/admin/delete_book/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    b = Book.query.get_or_404(book_id)
    try:
        os.remove(os.path.join(app.config['BOOKS_FOLDER'], b.filename))
    except Exception:
        app.logger.warning("Could not remove file from storage")
    db.session.delete(b)
    db.session.commit()
    flash('Book deleted')
    return redirect(url_for('admin_dashboard'))

@app.route('/teacher/books')
@login_required
def teacher_books():
    if current_user.role != 'teacher':
        flash('Access denied')
        return redirect(url_for('login'))

    books = Book.query.filter_by(uploader_id=current_user.id).order_by(Book.id.desc()).all()

    level_tabs = ['0','1','2','3','4','5','6','7','Red','Yellow','Green','Blue']

    books_by_level = {lvl: [] for lvl in level_tabs}

    for b in books:
        if b.levels:
            b_levels = [l.strip().capitalize() for l in b.levels.split(',')]
            for lvl in b_levels:
                if lvl.startswith("Level "):
                    lvl = lvl.split(" ")[1]
                if lvl.startswith("Grammar "):
                    lvl = "Grammar " + lvl.split(' ')[1]
                if lvl in books_by_level:
                    books_by_level[lvl].append(b)

    return render_template('teacher_books.html',
                           books_by_level=books_by_level,
                           level_tabs=level_tabs)

# ----------------------------
# Misc
# ----------------------------
@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

# ----------------------------
# Run (for local dev). On Railway you usually use gunicorn; this still allows `python bp.py` locally.
# ----------------------------
if __name__ == '__main__':
    # Use PORT env var (Railway sets PORT). Default to 8080.
    port = int(os.environ.get('PORT', 8080))
    # host 0.0.0.0 so Railway can bind
    app.run(host='0.0.0.0', port=port, debug=(os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'))
