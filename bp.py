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
from sqlalchemy import func  # add at top with other imports

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
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)


class PhonicsEntry(db.Model):
    __tablename__ = "phonics_entry"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    book_name = db.Column(db.String(100), nullable=False)   # ✅ NOT book_id
    time_taken = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    teacher = db.relationship(
        "User",
        backref="phonics_entries",
        foreign_keys=[created_by]
    )



with app.app_context():
    db.create_all()

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
from sqlalchemy.orm import joinedload

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))

    try:
        # Active tab and search
        tab = request.args.get('tab', 'teachers')   # default to teachers
        search = request.args.get('search', '').strip()

        # --- Fetch teachers ---
        teachers = User.query.filter_by(role='teacher').all()

        # --- Fetch books, optionally filtered by search ---
        books_query = Book.query.order_by(Book.uploaded_at.desc())
        if search:
            books_query = books_query.filter(Book.original_name.ilike(f"%{search}%"))
        books = books_query.all()

        # --- Fetch notifications ---
        notifications = Notification.query.order_by(Notification.created_at.desc()).all()

        # --- Fetch phonics entries with book & teacher relationships ---
        phonics_entries = PhonicsEntry.query.order_by(
            PhonicsEntry.id.desc()
        ).all()

        return render_template(
            'admin_dashboard.html',
            teachers=teachers,
            books=books,
            notifications=notifications,
            phonics_entries=phonics_entries,
            tab=tab,
            search_query=search
        )

    except Exception as e:
        app.logger.exception("Error in admin_dashboard")
        return f"Server Error: {str(e)}", 500


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
def admin_approve(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

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
    if current_user.role != 'admin':
        return redirect(url_for('login'))

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
@app.route("/admin/upload", methods=["GET", "POST"])
@login_required
def upload_book():
    if current_user.role != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        title = request.form.get("title")
        category = request.form.get("category")
        levels = request.form.getlist("levels")  # multiple select

        levels_str = ",".join(levels)

        filename = secure_filename(file.filename)
        file_data = file.read()
        
        book = Book(
            title=title,
            original_name=file.filename,
            filename=filename,
            category=category,
            levels=levels_str,
            uploader_id=current_user.id,
            file_data=file_data,
            file_size=len(file_data),
            content_type=file.content_type,
        )
        db.session.add(book)
        db.session.commit()

        flash("Book uploaded successfully!", "success")
        return redirect(url_for("admin_dashboard", tab="books"))

    return render_template("upload_book.html")

@app.route("/books")
@login_required
def books():
    level_tabs = ["1","2","3","4","5","6","7","Red","Yellow","Green","Blue","Hindi"]

    books = Book.query.all()
    books_by_level = { lvl: [] for lvl in level_tabs }

    for b in books:
        if b.levels:
            for lv in b.levels.split(","):
                lv = lv.strip()
                if lv in books_by_level:
                    books_by_level[lv].append(b)

    return render_template("teacher_books.html",
                           level_tabs=level_tabs,
                           books_by_level=books_by_level)


@app.route('/books/<int:book_id>')
@login_required
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('view_book.html', book=book)

import io
from flask import send_file, abort

@app.route('/books/stream/<int:book_id>')
@login_required
def stream_book(book_id):
    book = Book.query.get_or_404(book_id)

    if not book.file_data:
        abort(404)

    return send_file(
        io.BytesIO(book.file_data),
        as_attachment=False,
        download_name=book.original_name,
        mimetype=book.content_type or 'application/pdf'
    )



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
    if current_user.role != 'teacher':
        return redirect(url_for('login'))

    # LEVELS + COLOR LEVELS
    level_tabs = ["1","2","3","4","5","6","7","Red","Yellow","Green","Blue","Hindi"]

    # Get all books
    all_books = Book.query.all()

    # Organize books by level/color
    books_by_level = {lvl: [] for lvl in level_tabs}

    for book in all_books:
        # book.levels should contain comma-separated values like "1,Red,Green"
        if book.levels:
            assigned_levels = [x.strip() for x in book.levels.split(",")]
            for lvl in assigned_levels:
                if lvl in books_by_level:
                    books_by_level[lvl].append(book)

    return render_template(
        'teacher_dashboard.html',
        level_tabs=level_tabs,
        books_by_level=books_by_level,
        categories=['Story','Words','Workout','Comprehension','Test','Flashcards','Spoken Skill','Whiteboard','Letter Picture Cards']
    )


@app.route('/teacher/books')
@login_required
def teacher_books():
    if current_user.role != 'teacher':
        flash('Access denied')
        return redirect(url_for('login'))

    books = Book.query.filter_by(uploader_id=current_user.id).order_by(Book.id.desc()).all()

    # 11 tabs
    level_tabs = ['1','2','3','4','5','6','7','Red','Yellow','Green','Blue']

    # prepare dict
    books_by_level = {lvl: [] for lvl in level_tabs}

    for b in books:
        if b.levels:
            b_levels = [l.strip().capitalize() for l in b.levels.split(',')]
            for lvl in b_levels:
                # normalize numeric "Level 1" -> "1"
                if lvl.lower().startswith("level "):
                    lvl_key = lvl.split(" ", 1)[1]  # after "Level "
                else:
                    lvl_key = lvl  # Red/Yellow/Green/Blue as-is

                if lvl_key in books_by_level:
                    books_by_level[lvl_key].append(b)

    return render_template(
        'teacher_books.html',
        books_by_level=books_by_level,
        level_tabs=level_tabs
    )


@app.route("/delete_book/<int:book_id>", methods=["POST"])
@login_required
def delete_book(book_id):

    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for("admin_dashboard", tab="books"))

    book = Book.query.get_or_404(book_id)

    try:
        # delete completions linked to this book
        Completion.query.filter_by(book_id=book.id).delete(synchronize_session=False)

        # delete the book
        db.session.delete(book)
        db.session.commit()

        flash("Book deleted successfully", "success")

    except Exception as e:
        db.session.rollback()
        print("🔥 DELETE BOOK ERROR:", e)   # <-- Print the problem
        flash("Error deleting book", "danger")

    return redirect(url_for("admin_dashboard", tab="books"))





@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('user_identifier', '').strip()
        # Here you can implement your reset logic (send email etc.)
        flash(f'If an account exists for "{identifier}", instructions have been sent.')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route("/teacher/phonics", methods=["GET", "POST"])
@login_required
def teacher_phonics():
    if current_user.role != "teacher":
        return redirect(url_for("login"))

    if request.method == "POST":
        date = request.form.get("date")
        student_name = request.form.get("student_name")
        level = request.form.get("level")
        book_name = request.form.get("book_name")
        time_taken = request.form.get("time_taken")
        feedback = request.form.get("feedback", "")

        # Required field check
        if not (date and student_name and level and book_name and time_taken):
            flash("⚠️ Please fill all required fields.", "danger")
            return redirect(url_for("teacher_phonics"))

        try:
            entry = PhonicsEntry(
                date=date,
                student_name=student_name,
                level=level,
                book_name=book_name,       
                time_taken=time_taken, 
                feedback=feedback,
                created_by=current_user.id
            )

            db.session.add(entry)
            db.session.commit()
            flash("✅ Phonics Entry Saved Successfully!", "success")

        except Exception as e:
            db.session.rollback()
            flash("❌ Error saving entry. Try again.", "danger")
            app.logger.exception("Phonics Entry Error: %s", e)

        return redirect(url_for("teacher_phonics"))

    # GET request
    level_tabs = ["1", "2", "3", "4", "5", "6", "7",
                  "Red", "Yellow", "Green", "Blue", "Hindi"]

    books = Book.query.all()

    # book.levels might contain CSV text → FIXED
    books_by_level = {lvl: [] for lvl in level_tabs}
    for b in books:
        if b.levels:
            for lvl in level_tabs:
                if lvl in b.levels.split(","):
                    books_by_level[lvl].append(b)

    entries = PhonicsEntry.query.filter_by(
        created_by=current_user.id
    ).order_by(PhonicsEntry.id.desc()).all()

    categories = [
        'Story', 'Words', 'Workout', 'Comprehension', 'Test',
        'Flashcards', 'Spoken Skill', 'Whiteboard', 'Letter Picture Cards'
    ]

    return render_template(
        "teacher_dashboard.html",
        books=books,
        books_by_level=books_by_level,
        entries=entries,
        levels=level_tabs,
        level_tabs=level_tabs,
        categories=categories
    )











@app.route("/teacher/phonics/delete/<int:pid>", methods=["POST"])
@login_required
def delete_phonics_entry(pid):
    entry = PhonicsEntry.query.get_or_404(pid)

    if entry.created_by != current_user.id and current_user.role != "admin":
        flash("Not allowed", "danger")
        return redirect(url_for("teacher_dashboard"))

    db.session.delete(entry)
    db.session.commit()
    flash("Entry deleted", "success")
    return redirect(url_for("teacher_dashboard"))


@app.route("/admin/phonics")
@login_required
def admin_phonics():
    if current_user.role != "admin":
        return redirect(url_for("login"))

    entries = PhonicsEntry.query.options(
        joinedload(PhonicsEntry.book),
        joinedload(PhonicsEntry.teacher)
    ).order_by(PhonicsEntry.id.desc()).all()

    return render_template("admin_phonics.html", entries=entries)


@app.route("/admin/phonics/delete/<int:pid>", methods=["POST"])
@login_required
def admin_delete_phonics(pid):
    if current_user.role != "admin":
        return redirect(url_for("login"))

    entry = PhonicsEntry.query.get_or_404(pid)
    db.session.delete(entry)
    db.session.commit()
    flash("Entry deleted successfully.", "success")
    return redirect(url_for("admin_phonics"))


@app.route("/admin/phonics/download")
@login_required
def download_phonics_csv():
    if current_user.role != "admin":
        return redirect(url_for("login"))

    import csv
    from io import StringIO
    from flask import Response
    from sqlalchemy.orm import joinedload

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Student Name", "Level", "Book", "Time(min)", "Feedback", "Teacher"])

    # Use joinedload to fetch related book and user (teacher) in one query
    entries = PhonicsEntry.query.options(
        joinedload(PhonicsEntry.book)  # load book relationship
    ).order_by(PhonicsEntry.id.desc()).all()

    # Collect all teacher IDs to batch fetch names
    teacher_ids = list(set(e.created_by for e in entries))
    teachers = User.query.filter(User.id.in_(teacher_ids)).all()
    teacher_map = {t.id: t.name for t in teachers}

    for e in entries:
        teacher_name = teacher_map.get(e.created_by, "Unknown")
        writer.writerow([
            e.date,
            e.student_name,
            e.level,
            e.book.original_name if e.book else "",
            e.time_taken,
            e.feedback,
            teacher_name
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phonics_entries.csv"}
    )




# ----------------------------
# Run
# ----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT',8080))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG','false').lower()=='true')
