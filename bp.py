import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, jsonify, send_file, abort
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

# Secret Key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'devsecret')

# --- Database Config ---
# --- Database Config ---
db_url = os.environ.get("DATABASE_URL")

if db_url:
    # Railway public PostgreSQL URL fix
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://")

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    # Local SQLite fallback
    sqlite_path = f"sqlite:///{os.path.join(app.root_path, 'book_portal.db')}"
    app.config["SQLALCHEMY_DATABASE_URI"] = sqlite_path

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Storage Folder ---
STORAGE_FOLDER = os.environ.get('BOOKS_FOLDER') or os.path.join(app.root_path, 'books_storage')
os.makedirs(STORAGE_FOLDER, exist_ok=True)
app.config['BOOKS_FOLDER'] = STORAGE_FOLDER

db = SQLAlchemy(app)

# Allowed extensions
ALLOWED_EXT = {'pdf', 'jpg', 'jpeg', 'png'}

# Init extensions
login_manager = LoginManager(app)

login_manager.login_view = 'login'

# ----------------------------
# Models
# ----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), default='teacher', nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    allow_login = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    original_name = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    levels = db.Column(db.String(200))
    colors = db.Column(db.String(200))
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    file_data = db.Column(db.LargeBinary)        
    file_size = db.Column(db.Integer)
    content_type = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    completions = db.relationship("Completion", backref="book", cascade="all, delete")

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seen = db.Column(db.Boolean, default=False)

class Completion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey("book.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------------------
# Loader
# ----------------------------
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ----------------------------
# Ensure DB + admin exist
# ----------------------------
def create_db_and_admin():
    db.create_all()
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        try:
            admin = User(
                name='admin', role='admin', is_approved=True, allow_login=True
            )
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin'))
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Created default admin user")
        except Exception:
            db.session.rollback()

with app.app_context():
    create_db_and_admin()

# ----------------------------
# Helpers
# ----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def notify_admin(message):
    try:
        note = Notification(message=message)
        db.session.add(note)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to create notification")

# ----------------------------
# Routes — Auth
# ----------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip() or None
        password = request.form.get('password', '')
        if not name or not password:
            flash('Please enter name and password'); return redirect(url_for('register'))
        if name.lower() == 'admin':
            flash('Cannot register as admin'); return redirect(url_for('register'))
        if User.query.filter_by(name=name).first():
            flash('Name already taken'); return redirect(url_for('register'))
        if email and User.query.filter_by(email=email).first():
            flash('Email already registered'); return redirect(url_for('register'))
        u = User(name=name, email=email, role='teacher', is_approved=False, allow_login=False)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        notify_admin(f"New teacher registered: {name}")
        flash('Registered. Wait for admin approval.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(name=name).first()
        if not user or not user.check_password(password):
            flash('Invalid name or password'); return redirect(url_for('login'))
        if user.role == 'teacher':
            if not user.is_approved or not user.allow_login:
                flash('Your account is not approved or blocked'); return redirect(url_for('login'))
        login_user(user)
        flash('Login successful')
        return redirect(url_for('admin_dashboard') if user.role=='admin' else url_for('teacher_dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------------------------
# Admin dashboard
# ----------------------------
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied'); return redirect(url_for('login'))
    search = request.args.get('search','').strip()
    books_query = Book.query.order_by(Book.uploaded_at.desc())
    if search:
        books_query = books_query.filter(Book.original_name.ilike(f"%{search}%"))
    books = books_query.all()
    teachers = User.query.filter_by(role='teacher').all()
    notes = Notification.query.order_by(Notification.created_at.desc()).all()
    return render_template('admin_dashboard.html', teachers=teachers, books=books, notifications=notes, search_query=search)

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
def admin_approve(user_id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    u.is_approved = True
    u.allow_login = True
    db.session.commit()
    notify_admin(f"Admin approved teacher '{u.name}'")
    flash(f"Teacher {u.name} approved")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_allow/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_allow(user_id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    u.allow_login = not u.allow_login
    db.session.commit()
    notify_admin(f"Admin toggled allow_login for '{u.name}' -> {u.allow_login}")
    flash(f"Toggled login for {u.name}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete(user_id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    u = User.query.get_or_404(user_id)
    if u.role=='admin': flash("Cannot delete admin"); return redirect(url_for('admin_dashboard'))
    db.session.delete(u)
    db.session.commit()
    notify_admin(f"Admin deleted teacher '{u.name}'")
    flash("Teacher deleted")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_notifications', methods=['POST'])
@login_required
def admin_clear_notifications():
    if current_user.role != 'admin': return redirect(url_for('login'))
    Notification.query.delete(); db.session.commit()
    flash("Notifications cleared"); return redirect(url_for('admin_dashboard'))

# ----------------------------
# Book upload & view
# ----------------------------
@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_book():
    if current_user.role != 'admin': return redirect(url_for('login'))
    f = request.files.get('file')
    if not f or f.filename=='': flash('No file'); return redirect(request.url)
    if not allowed_file(f.filename): flash('File type not allowed'); return redirect(request.url)

    levels = request.form.getlist('levels')
    levels_str = ','.join(levels) if levels else '1'
    colors = request.form.getlist('colors')
    colors_str = ','.join(colors) if colors else ''
    category = request.form.get('category','Story')
    safe = secure_filename(f.filename)
    base, ext = os.path.splitext(safe)
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    stored = f"{base}_{timestamp}{ext}"
    path = os.path.join(app.config['BOOKS_FOLDER'], stored)
    f.save(path)
    b = Book(
        title=os.path.splitext(f.filename)[0],
        filename=stored,
        original_name=f.filename,
        levels=levels_str,
        colors=colors_str,
        category=category,
        uploader_id=current_user.id,
        file_size=os.path.getsize(path),
        content_type=f.content_type
    )
    with open(path,'rb') as file_bin:
        b.file_data = file_bin.read()
    db.session.add(b)
    db.session.commit()
    flash("Uploaded successfully")
    return redirect(url_for('admin_dashboard'))

@app.route('/books')
@login_required
def list_books():
    search = request.args.get('search','').strip()
    query = Book.query.order_by(Book.uploaded_at.desc())
    if search: query = query.filter(Book.original_name.ilike(f"%{search}%"))
    books = query.all()
    return render_template('teacher_books.html', books=books, search_query=search)

@app.route('/books/<int:book_id>')
@login_required
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    is_pdf = book.filename.lower().endswith(".pdf")
    return render_template('view_book.html', book=book, is_pdf=is_pdf)


@app.route('/books/stream/<int:book_id>')
@login_required
def stream_book(book_id):
    b = Book.query.get_or_404(book_id)
    path = os.path.join(app.config['BOOKS_FOLDER'], b.filename)
    if not os.path.exists(path): abort(404)
    return send_file(path, as_attachment=False, download_name=b.original_name, mimetype=b.content_type or 'application/pdf')

@app.route('/notify_attempt', methods=['POST'])
@login_required
def notify_attempt():
    data = request.get_json(silent=True) or request.form
    typ = data.get('type')
    book = data.get('book')
    if typ:
        notify_admin(f"{current_user.name} attempted {typ}" + (f" on {book}" if book else ''))
        return jsonify({'status':'ok'}),200
    return jsonify({'status':'bad request'}),400

# ----------------------------
# Teacher dashboard
# ----------------------------
@app.route('/teacher')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher': return redirect(url_for('login'))
    return render_template('teacher_dashboard.html')

@app.route('/teacher/books')
@login_required
def teacher_books():
    if current_user.role != 'teacher': return redirect(url_for('login'))
    books = Book.query.filter_by(uploader_id=current_user.id).order_by(Book.uploaded_at.desc()).all()
    level_tabs = ['0','1','2','3','4','5','6','7','Red','Yellow','Green','Blue']
    books_by_level = {lvl: [] for lvl in level_tabs}
    for b in books:
        if b.levels:
            for lvl in [l.strip().capitalize() for l in b.levels.split(',')]:
                if lvl in books_by_level: books_by_level[lvl].append(b)
    return render_template('teacher_books.html', books_by_level=books_by_level, level_tabs=level_tabs)

@app.route("/delete_book/<int:book_id>", methods=["POST"])
@login_required
def delete_book(book_id):
    if not current_user.role=='admin': flash("Unauthorized"); return redirect(url_for("admin_dashboard"))
    b = Book.query.get_or_404(book_id)
    try:
        Completion.query.filter_by(book_id=b.id).delete()
        db.session.delete(b)
        db.session.commit()
        flash("Book deleted successfully")
    except:
        db.session.rollback()
        flash("Error deleting book")
    return redirect(url_for("admin_dashboard"))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('user_identifier', '').strip()
        # Here you can implement your reset logic (send email etc.)
        flash(f'If an account exists for "{identifier}", instructions have been sent.')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


with app.app_context():
    db.create_all()

# ----------------------------
# Run
# ----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT',8080))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG','false').lower()=='true')
