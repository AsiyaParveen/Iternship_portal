from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
import os
from werkzeug.utils import secure_filename

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# These specific keys might be in Config or need to be set separately if they differ
app.config['SUPER_ADMIN_KEY'] = 'super123'  # Simple key for demonstration
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_DEFAULT_SENDER'] = app.config.get('MAIL_USERNAME')

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False) 
    status = db.Column(db.String(20), default='PENDING')
    profile_pic = db.Column(db.String(255), nullable=True)

class Internship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    poster_image = db.Column(db.String(255), nullable=True)
    
    company = db.relationship('User', foreign_keys=[company_id], backref=db.backref('company_internships', lazy=True))
    supervisor = db.relationship('User', foreign_keys=[supervisor_id], backref=db.backref('supervised_internships', lazy=True))

class SupervisorHiringPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    internship_id = db.Column(db.Integer, db.ForeignKey('internship.id'), nullable=True)
    poster_image = db.Column(db.String(255), nullable=True)
    
    company = db.relationship('User', backref=db.backref('supervisor_hiring_posts', lazy=True))
    internship = db.relationship('Internship', backref=db.backref('hiring_posts', lazy=True))

class SupervisorApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    cnic = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    education = db.Column(db.String(255), nullable=True)
    experience = db.Column(db.Text, nullable=False)
    cv_filename = db.Column(db.String(255), nullable=True)
    portfolio_link = db.Column(db.String(255), nullable=True)
    linkedin_link = db.Column(db.String(255), nullable=True)
    github_link = db.Column(db.String(255), nullable=True)
    hiring_post_id = db.Column(db.Integer, db.ForeignKey('supervisor_hiring_post.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='PENDING') # PENDING, APPROVED, REJECTED
    access_key = db.Column(db.String(50), unique=True, nullable=True)
    
    hiring_post = db.relationship('SupervisorHiringPost', backref=db.backref('applications', lazy=True))
    company = db.relationship('User', foreign_keys=[company_id])

class StudentApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    education = db.Column(db.String(255), nullable=False)
    institute = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    district = db.Column(db.String(100), nullable=False)
    internship_id = db.Column(db.Integer, db.ForeignKey('internship.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='PENDING') # PENDING, APPROVED, REJECTED
    access_key = db.Column(db.String(50), unique=True, nullable=True)

    internship = db.relationship('Internship', backref=db.backref('student_applications', lazy=True))
    student = db.relationship('User', backref=db.backref('internship_applications', lazy=True))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    terms_conditions = db.Column(db.Text, nullable=True)
    submission_date_time = db.Column(db.DateTime, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='ASSIGNED') # ASSIGNED, SUBMITTED, APPROVED

    student = db.relationship('User', foreign_keys=[student_id], backref=db.backref('tasks_assigned', lazy=True))
    supervisor = db.relationship('User', foreign_keys=[supervisor_id], backref=db.backref('tasks_created', lazy=True))

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_name = db.Column(db.String(100), nullable=True)
    internship_domain = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    district = db.Column(db.String(100), nullable=True)
    cnic = db.Column(db.String(15), nullable=True)
    github_link = db.Column(db.String(255), nullable=True)
    linkedin_link = db.Column(db.String(255), nullable=True)
    code_content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    status = db.Column(db.String(20), default='PENDING') # PENDING, APPROVED, REJECTED

    task = db.relationship('Task', backref=db.backref('submissions', lazy=True))
    student = db.relationship('User', backref=db.backref('submissions', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        # print(f"DEBUG: Loaded user {user.username} with role {user.role}")
        pass
    return user

@app.route('/')
def home():
    return redirect(url_for('login'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/pending')
def pending_page():
    return render_template('auth/pending.html')

# --- REGISTER ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists! Please choose another one.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password=hashed_pw,
            role=role,
            status='APPROVED' if role in ['supervisor', 'student'] else 'PENDING'
        )
        db.session.add(new_user)
        db.session.commit()
        if new_user.status == 'APPROVED':
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        return redirect(url_for('pending_page')) # Redirecting to pending for others
    return render_template('auth/register.html')

# --- LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            if user.role in ['super_admin', 'supervisor', 'student'] or user.status == 'APPROVED':
                login_user(user, remember=True)
                if user.role == 'super_admin':
                    return redirect(url_for('super_admin_dashboard'))
                elif user.role == 'company_admin':
                    return redirect(url_for('company_dashboard'))
                elif user.role == 'student':
                    return redirect(url_for('student_dashboard'))
                elif user.role == 'supervisor':
                    return redirect(url_for('supervisor_dashboard'))
                
                return redirect(url_for('login'))
            else:
                flash('Your account is pending approval by Super Admin.', 'warning')
                return redirect(url_for('pending_page'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- SUPER ADMIN LOGIN (KEY BASED) ---
@app.route('/super-admin-login', methods=['GET', 'POST'])
def super_admin_login():
    if request.method == 'POST':
        key_attempt = request.form.get('key')
        if key_attempt == app.config['SUPER_ADMIN_KEY']:
            # Find the Super Admin user
            admin_user = User.query.filter_by(role='super_admin').first()
            if admin_user:
                login_user(admin_user)
                return redirect(url_for('super_admin_dashboard'))
            else:
                flash('Super Admin User not found in database.', 'danger')
        else:
            flash('Invalid Security Key', 'danger')
    return render_template('super_admin/login.html')

# --- SUPER ADMIN ---
@app.route('/super_admin/dashboard')
@login_required
def super_admin_dashboard():
    if current_user.role != 'super_admin':
        return f"Unauthorized: Authed={current_user.is_authenticated}, Role='{getattr(current_user, 'role', 'N/A')}', Required='super_admin'", 403
    
    # Only pending companies for Super Admin now
    companies_count = User.query.filter_by(status='PENDING', role='company_admin').count()
    
    supervisor_posts_count = SupervisorHiringPost.query.count()
    internship_posts_count = Internship.query.count()
    
    return render_template('super_admin/dashboard.html', 
                           companies_count=companies_count, 
                           supervisor_posts_count=supervisor_posts_count,
                           internship_posts_count=internship_posts_count)

@app.route('/super_admin/companies')
@login_required
def manage_companies():
    if current_user.role != 'super_admin': return "Unauthorized", 403
    pending_companies = User.query.filter_by(status='PENDING', role='company_admin').all()
    all_internships = Internship.query.all()
    all_hiring_posts = SupervisorHiringPost.query.all()
    
    return render_template('super_admin/companies.html', 
                           users=pending_companies, 
                           internships=all_internships, 
                           hiring_posts=all_hiring_posts)

@app.route('/super_admin/supervisors')
@login_required
def super_admin_manage_supervisors():
    if current_user.role != 'super_admin': return "Unauthorized", 403
    pending_supervisors = User.query.filter_by(status='PENDING', role='supervisor').all()
    hiring_posts = SupervisorHiringPost.query.all()
    return render_template('super_admin/supervisors.html', users=pending_supervisors, hiring_posts=hiring_posts)

@app.route('/super_admin/students')
@login_required
def manage_students():
    if current_user.role != 'super_admin': return "Unauthorized", 403
    pending_students = User.query.filter_by(status='PENDING', role='student').all()
    internships = Internship.query.all()
    return render_template('super_admin/students.html', users=pending_students, internships=internships)

@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'APPROVED'
    db.session.commit()
    return redirect(url_for('super_admin_dashboard'))

@app.route('/reject_user/<int:user_id>')
@login_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('super_admin_dashboard'))

# --- COMPANY ADMIN ---
@app.route('/company/dashboard')
@login_required
def company_dashboard():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    my_posts = Internship.query.filter_by(company_id=current_user.id).all()
    hiring_posts = SupervisorHiringPost.query.filter_by(company_id=current_user.id).all()
    # Count pending applications
    pending_apps_count = SupervisorApplication.query.filter_by(company_id=current_user.id, status='PENDING').count()
    return render_template('company_admin/dashboard.html', posts=my_posts, hiring_posts=hiring_posts, pending_apps_count=pending_apps_count)

@app.route('/supervisor/apply/<int:post_id>', methods=['GET', 'POST'])
@login_required
def apply_for_supervisor(post_id):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    post = SupervisorHiringPost.query.get_or_404(post_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        cnic = request.form.get('cnic')
        email = request.form.get('email')
        education = request.form.get('education')
        experience = request.form.get('experience')
        portfolio = request.form.get('portfolio')
        linkedin = request.form.get('linkedin')
        github = request.form.get('github')
        
        # File Handling
        cv_filename = None
        if 'cv' in request.files:
            file = request.files['cv']
            if file and allowed_file(file.filename):
                cv_filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], cv_filename))
        
        application = SupervisorApplication(
            name=name,
            cnic=cnic,
            email=email,
            education=education,
            experience=experience,
            cv_filename=cv_filename,
            portfolio_link=portfolio,
            linkedin_link=linkedin,
            github_link=github,
            hiring_post_id=post_id,
            company_id=post.company_id,
            status='PENDING'
        )
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('supervisor_dashboard'))
        
    return render_template('supervisor/apply.html', post=post)

@app.route('/company/applications')
@login_required
def view_supervisor_applications():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    
    applications = SupervisorApplication.query.filter_by(company_id=current_user.id).all()
    return render_template('company_admin/review_applications.html', applications=applications)

@app.route('/company/process_application/<int:app_id>/<string:action>')
@login_required
def process_supervisor_application(app_id, action):
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    
    application = SupervisorApplication.query.get_or_404(app_id)
    if application.company_id != current_user.id:
        return "Unauthorized", 403
    
    if action == 'approve':
        application.status = 'APPROVED'
        # Generate a simple 8-char random key
        import random, string
        access_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        application.access_key = access_key
        
        # Send Email Notification
        try:
            msg = Message(
                "Supervisor Application Approved!",
                recipients=[application.email]
            )
            msg.body = f"""
            Hello {application.name},
            
            Congratulations! Your application to be a supervisor for the internship program at {current_user.username} has been APPROVED.
            
            You can now access your supervisor dashboard using the following access key:
            
            ACCESS KEY: {access_key}
            
            Please go to the supervisor login page and enter this key to open your dashboard.
            
            Best regards,
            {current_user.username} Team
            """
            mail.send(msg)
            flash(f'Application Approved and Notification Email Sent! Key: {access_key}', 'success')
        except Exception as e:
            print(f"Error sending email: {e}")
            flash(f'Application Approved! Key: {access_key} (Note: Email notification failed)', 'warning')
            
    elif action == 'reject':
        application.status = 'REJECTED'
        flash('Application Rejected.', 'warning')
        
    db.session.commit()
    return redirect(url_for('view_supervisor_applications'))

@app.route('/supervisor/verify_key', methods=['POST'])
@login_required
def verify_supervisor_key():
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    key_attempt = request.form.get('access_key')
    application = SupervisorApplication.query.filter_by(access_key=key_attempt, email=current_user.email).first()
    
    if application and application.status == 'APPROVED':
        return redirect(url_for('supervisor_portal', app_id=application.id))
    else:
        flash('Invalid Access Key or Application not approved.', 'danger')
        return redirect(url_for('supervisor_dashboard'))

@app.route('/supervisor/portal/<int:app_id>')
@login_required
def supervisor_portal(app_id):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    application = SupervisorApplication.query.get_or_404(app_id)
    # Basic security check
    if application.email != current_user.email:
        return "Unauthorized", 403
        
    # Get students assigned to the internship associated with this supervisor application
    # Or students explicitly assigned to this supervisor
    students = []
    if application.hiring_post and application.hiring_post.internship_id:
        internship_id = application.hiring_post.internship_id
        students = StudentApplication.query.filter_by(internship_id=internship_id, status='APPROVED').all()
    else:
        # Fallback: All approved students for the company where this user is the assigned supervisor
        from sqlalchemy import or_
        students = StudentApplication.query.join(Internship).filter(
            Internship.company_id == application.company_id,
            Internship.supervisor_id == current_user.id,
            StudentApplication.status == 'APPROVED'
        ).all()
        
    return render_template('supervisor/portal.html', application=application, students=students)

@app.route('/company/post_internship', methods=['GET', 'POST'])
@login_required
def post_internship():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        domain = request.form.get('domain')
        
        filename = None
        if 'poster_image' in request.files:
            file = request.files['poster_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Ensure directory exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        new_post = Internship(
            title=title, 
            description=description, 
            domain=domain, 
            company_id=current_user.id,
            poster_image=filename
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Internship post created successfully!', 'success')
        return redirect(url_for('company_dashboard'))
    return render_template('company_admin/post_internship.html')

@app.route('/company/profile', methods=['GET', 'POST'])
@login_required
def company_profile():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        print(f"DEBUG: Profile Update - Username: {username}, Email: {email}")
        
        # Check if username or email already taken (excluding current user)
        if User.query.filter(User.email == email, User.id != current_user.id).first():
            print("DEBUG: Email already exists")
            flash('Email already exists!', 'danger')
            return redirect(url_for('company_profile'))
            
        if User.query.filter(User.username == username, User.id != current_user.id).first():
            print("DEBUG: Username already exists")
            flash('Username already exists!', 'danger')
            return redirect(url_for('company_profile'))
        
        current_user.username = username
        current_user.email = email
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            print(f"DEBUG: Profile Pic uploaded - Filename: {file.filename}")
            if file and allowed_file(file.filename):
                import time
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(file.filename)
                # Ensure filename is unique by adding user ID and timestamp to bust cache
                filename = f"user_{current_user.id}_{int(time.time())}.{ext}"
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                print(f"DEBUG: Saved profile pic to {save_path}")
                current_user.profile_pic = filename
            elif file and not allowed_file(file.filename):
                print(f"DEBUG: Invalid file type: {file.filename}")
                flash('Invalid file type! Allowed: png, jpg, jpeg, gif', 'danger')
                return redirect(url_for('company_profile'))
        
        db.session.add(current_user)
        db.session.commit()
        print("DEBUG: Profile updated and committed to DB")
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('company_profile'))
        
    return render_template('company_admin/edit_profile.html')

@app.route('/supervisor/profile', methods=['POST'])
@login_required
def supervisor_profile_update():
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
        
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            import time
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(file.filename)
            filename = f"user_{current_user.id}_{int(time.time())}.{ext}"
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_pic = filename
            db.session.commit()
            flash('Profile picture updated!', 'success')
        else:
            flash('Invalid file type!', 'danger')
            
    # Redirect back to the portal. We need the app_id. 
    # Since we don't have it easily, we can find the approved application for this user.
    application = SupervisorApplication.query.filter_by(email=current_user.email, status='APPROVED').first()
    if application:
        return redirect(url_for('supervisor_portal', app_id=application.id))
    return redirect(url_for('supervisor_dashboard'))

@app.route('/company/edit_internship/<int:internship_id>', methods=['GET', 'POST'])
@login_required
def edit_internship(internship_id):
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    
    internship = Internship.query.get_or_404(internship_id)
    if internship.company_id != current_user.id:
        return "Unauthorized", 403
        
    if request.method == 'POST':
        internship.title = request.form.get('title')
        internship.description = request.form.get('description')
        internship.domain = request.form.get('domain')
        
        if 'poster_image' in request.files:
            file = request.files['poster_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                internship.poster_image = filename
                
        db.session.commit()
        flash('Internship post updated successfully!', 'success')
        return redirect(url_for('company_dashboard'))
        
    return render_template('company_admin/edit_internship.html', internship=internship)

@app.route('/company/manage_supervisors')
@login_required
def company_manage_supervisors():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    
    # Get all approved supervisors in the system
    all_supervisors = User.query.filter_by(role='supervisor', status='APPROVED').all()
    # Get internships that need supervisors
    my_internships = Internship.query.filter_by(company_id=current_user.id).all()
    
    return render_template('company_admin/manage_supervisors.html', supervisors=all_supervisors, internships=my_internships)

@app.route('/company/assign_supervisor', methods=['POST'])
@login_required
def assign_supervisor():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
    internship_id = request.form.get('internship_id')
    supervisor_id = request.form.get('supervisor_id')
    
    internship = Internship.query.get_or_404(internship_id)
    if internship.company_id == current_user.id:
        internship.supervisor_id = supervisor_id
        db.session.commit()
        flash('Supervisor assigned successfully!', 'success')
    return redirect(url_for('company_manage_supervisors'))

@app.route('/company/create_supervisor_hiring_post', methods=['POST'])
@login_required
def create_supervisor_hiring_post():
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
        
    title = request.form.get('title')
    description = request.form.get('description')
    domain = request.form.get('domain')
    internship_id = request.form.get('internship_id')
    
    filename = None
    if 'poster_image' in request.files:
        file = request.files['poster_image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
    new_hiring_post = SupervisorHiringPost(
        title=title,
        description=description,
        domain=domain,
        company_id=current_user.id,
        internship_id=internship_id if internship_id else None,
        poster_image=filename
    )
    db.session.add(new_hiring_post)
    db.session.commit()
    flash('Supervisor hiring post created!', 'success')
    return redirect(url_for('company_manage_supervisors'))

@app.route('/company/edit_supervisor_hiring_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_supervisor_hiring_post(post_id):
    if current_user.role != 'company_admin':
        return "Unauthorized", 403
        
    post = SupervisorHiringPost.query.get_or_404(post_id)
    if post.company_id != current_user.id:
        return "Unauthorized", 403
        
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.description = request.form.get('description')
        post.domain = request.form.get('domain')
        post.internship_id = request.form.get('internship_id') or None
        
        if 'poster_image' in request.files:
            file = request.files['poster_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                post.poster_image = filename
                
        db.session.commit()
        flash('Supervisor hiring post updated!', 'success')
        return redirect(url_for('company_dashboard'))
        
    my_internships = Internship.query.filter_by(company_id=current_user.id).all()
    return render_template('company_admin/edit_supervisor_hiring_post.html', post=post, internships=my_internships)

# --- STUDENT DASHBOARD ---
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return "Unauthorized", 403
    internships = Internship.query.all()
    # Check if student has any approved applications to show in a different section or just list all
    my_applications = StudentApplication.query.filter_by(student_id=current_user.id).all()
    return render_template('student/dashboard.html', internships=internships, my_applications=my_applications)

@app.route('/student/apply/<int:internship_id>', methods=['GET', 'POST'])
@login_required
def apply_for_internship(internship_id):
    if current_user.role != 'student':
        return "Unauthorized", 403
    
    internship = Internship.query.get_or_404(internship_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        education = request.form.get('education')
        institute = request.form.get('institute')
        domain = request.form.get('domain')
        city = request.form.get('city')
        district = request.form.get('district')
        
        application = StudentApplication(
            name=name,
            education=education,
            institute=institute,
            domain=domain,
            city=city,
            district=district,
            internship_id=internship_id,
            student_id=current_user.id,
            status='PENDING'
        )
        db.session.add(application)
        db.session.commit()
        flash('Internship application submitted successfully!', 'success')
        return redirect(url_for('student_dashboard'))
        
    return render_template('student/apply.html', internship=internship)

@app.route('/student/verify_key', methods=['POST'])
@login_required
def verify_student_key():
    if current_user.role != 'student':
        return "Unauthorized", 403
    
    key_attempt = request.form.get('access_key')
    application = StudentApplication.query.filter_by(access_key=key_attempt, student_id=current_user.id).first()
    
    if application and application.status == 'APPROVED':
        return redirect(url_for('student_portal', app_id=application.id))
    else:
        flash('Invalid Access Key or Application not approved.', 'danger')
        return redirect(url_for('student_dashboard'))

@app.route('/student/portal/<int:app_id>')
@login_required
def student_portal(app_id):
    if current_user.role != 'student':
        return "Unauthorized", 403
    
    application = StudentApplication.query.get_or_404(app_id)
    if application.student_id != current_user.id:
        return "Unauthorized", 403
        
    tasks = Task.query.filter_by(student_id=current_user.id, status='ASSIGNED').all()
    submissions = Submission.query.filter_by(student_id=current_user.id).all()
    
    return render_template('student/portal.html', application=application, tasks=tasks, submissions=submissions)

@app.route('/student/submit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def submit_task(task_id):
    if current_user.role != 'student':
        return "Unauthorized", 403
    
    task = Task.query.get_or_404(task_id)
    if task.student_id != current_user.id:
        return "Unauthorized", 403
        
    application = StudentApplication.query.filter_by(student_id=current_user.id, internship_id=task.student.supervised_internships[0].id if task.student.supervised_internships else None).first()
    # Actually, we can just get the application linked to the internship of the task
    # For now, let's just get the first approved application for this student
    application = StudentApplication.query.filter_by(student_id=current_user.id, status='APPROVED').first()

    if request.method == 'POST':
        submission = Submission(
            task_id=task_id,
            student_id=current_user.id,
            student_name=request.form.get('student_name'),
            internship_domain=request.form.get('internship_domain'),
            email=request.form.get('email'),
            city=request.form.get('city'),
            district=request.form.get('district'),
            cnic=request.form.get('cnic'),
            github_link=request.form.get('github_link'),
            linkedin_link=request.form.get('linkedin_link'),
            code_content=request.form.get('code_content')
        )
        
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                submission.file_path = filename
        
        db.session.add(submission)
        task.status = 'SUBMITTED'
        db.session.commit()
        flash('Task submitted successfully!', 'success')
        return redirect(url_for('student_portal', app_id=application.id if application else 0))
        
    return render_template('student/submit_task.html', task=task, application=application)

@app.route('/student/certificate/<int:submission_id>')
@login_required
def student_certificate(submission_id):
    if current_user.role != 'student':
        return "Unauthorized", 403
    
    submission = Submission.query.get_or_404(submission_id)
    if submission.student_id != current_user.id or submission.status != 'APPROVED':
        flash('Certificate not available or not yet approved.', 'warning')
        return redirect(url_for('student_dashboard'))
        
    return render_template('student/certificate.html', submission=submission)

@app.route('/student/profile_update', methods=['POST'])
@login_required
def student_profile_update():
    if current_user.role != 'student':
        return "Unauthorized", 403
        
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            import time
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(file.filename)
            filename = f"user_{current_user.id}_{int(time.time())}.{ext}"
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_pic = filename
            db.session.commit()
            flash('Profile picture updated!', 'success')
            
    # Need to redirect back to the portal if they were in one, or dashboard
    app_id = request.form.get('app_id')
    if app_id:
        return redirect(url_for('student_portal', app_id=app_id))
    return redirect(url_for('student_dashboard'))

# --- SUPERVISOR DASHBOARD ---
@app.route('/supervisor/dashboard')
@login_required
def supervisor_dashboard():
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    hiring_posts = SupervisorHiringPost.query.all()
    # Also get my approved supervisor applications to show portal links
    my_applications = SupervisorApplication.query.filter_by(email=current_user.email, status='APPROVED').all()
    return render_template('supervisor/dashboard.html', hiring_posts=hiring_posts, my_applications=my_applications)

@app.route('/supervisor/student_requests/<int:app_id>')
@login_required
def view_student_requests(app_id):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    application = SupervisorApplication.query.get_or_404(app_id)
    if application.email != current_user.email:
        return "Unauthorized", 403
        
    if application.hiring_post and application.hiring_post.internship_id:
        internship_id = application.hiring_post.internship_id
        student_apps = StudentApplication.query.filter_by(internship_id=internship_id).all()
    else:
        # If it's a general program, show all student requests for this company
        # that aren't already filtered out (or just all for simplicity if it's general)
        student_apps = StudentApplication.query.join(Internship).filter(
            Internship.company_id == application.company_id
        ).all()
    
    return render_template('supervisor/student_requests.html', application=application, student_apps=student_apps)

@app.route('/supervisor/process_student_application/<int:app_id>/<int:student_app_id>/<string:action>')
@login_required
def process_student_application(app_id, student_app_id, action):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    supervisor_app = SupervisorApplication.query.get_or_404(app_id)
    if supervisor_app.email != current_user.email:
        return "Unauthorized", 403
        
    student_app = StudentApplication.query.get_or_404(student_app_id)
    
    if action == 'approve':
        student_app.status = 'APPROVED'
        import random, string
        access_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        student_app.access_key = access_key
        flash(f'Student application approved! Key: {access_key}', 'success')
    elif action == 'reject':
        student_app.status = 'REJECTED'
        flash('Student application rejected.', 'warning')
        
    db.session.commit()
    return redirect(url_for('view_student_requests', app_id=app_id))

@app.route('/supervisor/assign_task/<int:app_id>/<int:student_id>', methods=['GET', 'POST'])
@login_required
def assign_task(app_id, student_id):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
        
    supervisor_app = SupervisorApplication.query.get_or_404(app_id)
    student = User.query.get_or_404(student_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        terms = request.form.get('terms')
        deadline_str = request.form.get('deadline')
        
        from datetime import datetime
        deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
        
        new_task = Task(
            title=title,
            description=description,
            terms_conditions=terms,
            submission_date_time=deadline,
            student_id=student_id,
            supervisor_id=current_user.id,
            status='ASSIGNED'
        )
        db.session.add(new_task)
        db.session.commit()
        flash('Task assigned successfully!', 'success')
        return redirect(url_for('supervisor_portal', app_id=app_id))
        
    return render_template('supervisor/assign_task.html', application=supervisor_app, student=student)

@app.route('/supervisor/view_submissions/<int:app_id>')
@login_required
def supervisor_view_submissions(app_id):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    supervisor_app = SupervisorApplication.query.get_or_404(app_id)
    if supervisor_app.email != current_user.email:
        return "Unauthorized", 403
        
    # Get all submissions for tasks created by this supervisor
    submissions = Submission.query.join(Task).filter(Task.supervisor_id == current_user.id).all()
    
    return render_template('supervisor/view_submissions.html', application=supervisor_app, submissions=submissions)

@app.route('/supervisor/process_submission/<int:app_id>/<int:submission_id>/<string:action>')
@login_required
def process_submission(app_id, submission_id, action):
    if current_user.role != 'supervisor':
        return "Unauthorized", 403
    
    supervisor_app = SupervisorApplication.query.get_or_404(app_id)
    if supervisor_app.email != current_user.email:
        return "Unauthorized", 403

    submission = Submission.query.get_or_404(submission_id)
    if submission.task.supervisor_id != current_user.id:
        return "Unauthorized", 403
        
    if action == 'approve':
        submission.status = 'APPROVED'
        submission.task.status = 'APPROVED'
        flash('Submission approved! Certificate is now available to the student.', 'success')
    elif action == 'reject':
        submission.status = 'REJECTED'
        submission.task.status = 'ASSIGNED'
        flash('Submission rejected.', 'warning')
        
    db.session.commit()
    return redirect(url_for('supervisor_view_submissions', app_id=app_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='super_admin').first():
            hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(username='AdminUser', email='admin@portal.com', password=hashed_pw, role='super_admin', status='APPROVED')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)