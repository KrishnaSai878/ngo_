from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message as MailMessage
import os
from datetime import datetime, timedelta, timezone
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import database models and utilities
from database.models import db, User, NGO, Volunteer, Donor, Event, TimeSlot, Booking, Message, Resource, Project, AdminAuditLog, AdminRole, AdminUserRole
from database.queries import init_queries
from admin_decorators import (
    admin_required, admin_permission_required, log_admin_action, get_admin_permissions,
    generate_csrf_token, validate_csrf_token, rate_limit_admin_requests, validate_admin_input
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
# Database configuration - requires DATABASE_URL to be set in environment
if not os.environ.get('DATABASE_URL'):
    raise ValueError("DATABASE_URL environment variable must be set. Please configure your database connection.")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 280
}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Security settings
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email settings
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = str(os.environ.get('MAIL_USE_TLS', 'True')).lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Initialize database
db.init_app(app)

# Initialize other extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")
csrf = CSRFProtect(app)
mail = Mail(app)

# Initialize queries
queries = init_queries(db, {
    'User': User, 'NGO': NGO, 'Volunteer': Volunteer, 'Donor': Donor,
    'Event': Event, 'TimeSlot': TimeSlot, 'Booking': Booking, 'Message': Message,
    'Resource': Resource, 'Project': Project
})

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Force HTTPS in production
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Ensure csrf_token() is available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf, current_year=datetime.now(timezone.utc).year)

# Default admin context for templates so sidebar badges/visibility work on every admin page
@app.context_processor
def inject_admin_defaults():
    try:
        # Compute light-weight stats used in admin sidebar badges
        base_stats = {
            'pending_users': User.query.filter_by(is_verified=False).count(),
            'pending_ngos': NGO.query.filter_by(is_verified=False).count(),
        }
        # Compute admin permissions for current user if authenticated
        perms = get_admin_permissions(current_user) if current_user.is_authenticated else []
        return dict(stats=base_stats, admin_permissions=perms)
    except Exception:
        # In case DB is unavailable during error pages, return safe defaults
        return dict(stats={'pending_users': 0, 'pending_ngos': 0}, admin_permissions=[])

# Ensure the current admin has a Super Admin role with full permissions
def ensure_super_admin(user):
    try:
        if not user.is_authenticated or getattr(user, 'role', None) != 'admin':
            return
        # Define full permissions used in the app
        full_perms = {
            'manage_users': True,
            'create_users': True,
            'delete_users': True,
            'export_data': True,
            'manage_ngos': True,
            'manage_events': True,
            'manage_content': True,
            'view_analytics': True,
            'view_audit_logs': True,
            'manage_roles': True,
            'manage_settings': True,
        }
        role = AdminRole.query.filter_by(name='Super Admin').first()
        if not role:
            role = AdminRole(name='Super Admin', description='All permissions', permissions=json.dumps(full_perms), is_active=True)
            db.session.add(role)
            db.session.commit()
        else:
            # Keep role permissions up to date
            try:
                current = role.get_permissions()
            except Exception:
                current = {}
            if any(not current.get(k) for k in full_perms.keys()):
                role.permissions = json.dumps(full_perms)
                db.session.commit()
        # Assign role to user if not already
        assignment = AdminUserRole.query.filter_by(user_id=user.id, role_id=role.id, is_active=True).first()
        if not assignment:
            assignment = AdminUserRole(user_id=user.id, role_id=role.id, is_active=True)
            db.session.add(assignment)
            db.session.commit()
    except Exception as _e:
        # Do not break the request if role assignment fails
        app.logger.error(f"Failed to ensure Super Admin role: {_e}")

# Friendly CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(f'Form security check failed: {e.description}', 'error')
    return redirect(request.referrer or url_for('index'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def index():
    # If an admin visits the root, take them to the admin dashboard
    # Allow bypass via query when an admin page error redirected here
    if request.args.get('no_admin_redirect') != '1' and current_user.is_authenticated and getattr(current_user, 'role', None) == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        phone = data.get('phone')

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            first_name=first_name,
            last_name=last_name,
            phone=phone
        )
        db.session.add(user)
        db.session.commit()

        # Create role-specific profile
        if role == 'ngo':
            ngo = NGO(
                user_id=user.id,
                organization_name=data.get('organization_name'),
                description=data.get('description'),
                mission=data.get('mission'),
                website=data.get('website'),
                address=data.get('address'),
                city=data.get('city'),
                state=data.get('state'),
                zip_code=data.get('zip_code'),
                email=data.get('email'),
                category=data.get('category'),
                established_year=data.get('established_year')
            )
            db.session.add(ngo)
        elif role == 'volunteer':
            # Handle skills and interests - check if they exist in form data
            skills = data.getlist('skills') if 'skills' in data else []
            interests = data.getlist('interests') if 'interests' in data else []
            
            volunteer = Volunteer(
                user_id=user.id,
                bio=data.get('bio'),
                skills=json.dumps(skills),
                interests=json.dumps(interests)
            )
            db.session.add(volunteer)
        elif role == 'donor':
            donor = Donor(
                user_id=user.id,
                company_name=data.get('company_name')
            )
            db.session.add(donor)

        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simple rate limiting - check session for failed attempts
        failed_attempts = session.get('failed_login_attempts', 0)
        if failed_attempts >= 5:
            flash('Too many failed login attempts. Please try again later.', 'error')
            return render_template('login.html')
        
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            # Reset failed attempts on successful login
            session.pop('failed_login_attempts', None)
            login_user(user)
            # Use timezone-aware now, then strip tzinfo to keep DB naive UTC
            user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()
            # Redirect admins straight to admin dashboard; others use role router
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'dashboard'))
        else:
            # Increment failed attempts
            session['failed_login_attempts'] = failed_attempts + 1
            flash('Invalid email or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# File upload route
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > MAX_FILE_SIZE:
            flash('File too large. Maximum size is 16MB', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to prevent filename conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            flash('File uploaded successfully', 'success')
            return redirect(request.url)
        else:
            flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, PDF, DOC, DOCX', 'error')
            return redirect(request.url)
            
    except Exception as e:
        flash(f'File upload failed: {str(e)}', 'error')
        return redirect(request.url)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'ngo':
        return redirect(url_for('ngo_dashboard'))
    elif current_user.role == 'volunteer':
        return redirect(url_for('volunteer_dashboard'))
    elif current_user.role == 'donor':
        return redirect(url_for('donor_dashboard'))
    else:
        flash('Unknown user role. Please contact support.', 'error')
        return redirect(url_for('index'))



@app.route('/ngo/dashboard')
@login_required
def ngo_dashboard():
    if current_user.role != 'ngo':
        flash('Access denied. NGO privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get NGO statistics and data using queries
    stats = queries.get_ngo_stats(ngo.id)
    events = Event.query.filter_by(ngo_id=ngo.id).order_by(Event.created_at.desc()).limit(5).all()
    
    return render_template('ngo/dashboard.html', ngo=ngo, events=events, **stats)

@app.route('/volunteer/dashboard')
@login_required
def volunteer_dashboard():
    if current_user.role != 'volunteer':
        flash('Access denied. Volunteer privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
    if not volunteer:
        flash('Volunteer profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get volunteer statistics and data using queries
    stats = queries.get_volunteer_stats(volunteer.id)
    bookings = queries.get_user_bookings(current_user.id, 'confirmed')[:5]
    recommended_events = queries.get_recommended_events(volunteer.id, 5)
    
    # Get completed events count
    completed_events = Booking.query.filter_by(
        volunteer_id=volunteer.id, 
        status='completed'
    ).count()
    
    return render_template('volunteer/dashboard.html', 
                         volunteer=volunteer, 
                         bookings=bookings, 
                         recommended_events=recommended_events,
                         completed_events=completed_events,
                         **stats)

@app.route('/donor/dashboard')
@login_required
def donor_dashboard():
    if current_user.role != 'donor':
        return redirect(url_for('dashboard'))
    
    donor = Donor.query.filter_by(user_id=current_user.id).first()
    if not donor:
        flash('Donor profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get donor statistics
    donation_history = donor.get_donation_history()
    # Convert USD amounts to INR (1 USD = 83 INR approximate conversion rate)
    USD_TO_INR_RATE = 83
    total_donated_usd = sum(float(d.get('amount', 0)) for d in donation_history)
    total_donated = total_donated_usd * USD_TO_INR_RATE
    total_donations = len(donation_history)
    
    # Get unique organizations supported
    organizations_supported = len(set(d.get('organization', 'Unknown') for d in donation_history))
    
    # Estimate lives impacted (rough calculation) - adjust for INR
    lives_impacted = int(total_donated * 0.03)  # Rough estimate: ₹1 = 0.03 lives impacted
    
    # Get recommended NGOs
    recommended_ngos = queries.get_recommended_ngos(donor.id, limit=5) if queries else []
    
    # Get all NGOs for quick donation form
    all_ngos = NGO.query.filter_by(is_verified=True).all()
    
    return render_template('donor/dashboard.html', 
                         donor=donor,
                         total_donated=total_donated,
                         total_donations=total_donations,
                         organizations_supported=organizations_supported,
                         lives_impacted=lives_impacted,
                         donation_history=donation_history,
                         recommended_ngos=recommended_ngos,
                         all_ngos=all_ngos)

@app.route('/volunteer/achievements')
@login_required
def volunteer_achievements():
    if current_user.role != 'volunteer':
        flash('Access denied. Volunteer privileges required.', 'error')
        return redirect(url_for('dashboard'))

    volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
    if not volunteer:
        flash('Volunteer profile not found.', 'error')
        return redirect(url_for('dashboard'))

    stats = queries.get_volunteer_stats(volunteer.id)
    recent_bookings = queries.get_user_bookings(current_user.id)[:10]

    return render_template(
        'volunteer/achievements.html',
        volunteer=volunteer,
        recent_bookings=recent_bookings,
        **stats
    )

@app.route('/volunteers/leaderboard')
def volunteers_leaderboard():
    points_leaders = queries.get_volunteer_leaderboard(limit=10)
    hours_leaders = queries.get_hours_leaderboard(limit=10)
    return render_template(
        'volunteers_leaderboard.html',
        points_leaders=points_leaders,
        hours_leaders=hours_leaders
    )

@app.route('/admin/test-email')
@admin_required
def admin_test_email():
    try:
        to_addr = request.args.get('to') or app.config.get('MAIL_USERNAME')
        if not to_addr:
            flash('MAIL_USERNAME is not configured and no ?to=email provided', 'error')
            return redirect(url_for('admin_dashboard'))

        msg = MailMessage(
            subject='NGO Connect Test Email',
            sender=app.config.get('MAIL_USERNAME'),
            recipients=[to_addr],
            body='This is a test email from NGO Connect.'
        )
        mail.send(msg)
        flash(f'Test email sent to {to_addr}', 'success')
    except Exception as e:
        flash(f'Failed to send test email: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/ngos')
def ngos_directory():
    search_term = request.args.get('q', '')
    category = request.args.get('category') or None
    city = request.args.get('city') or None
    ngos = queries.search_ngos(search_term, category=category, city=city)
    return render_template('ngos.html', ngos=ngos, q=search_term, category=category, city=city)

@app.route('/ngos/<int:ngo_id>/opportunities')
def ngo_opportunities(ngo_id: int):
    ngo = NGO.query.get_or_404(ngo_id)
    events = Event.query.filter_by(ngo_id=ngo.id, is_active=True).order_by(Event.start_date.asc()).all()
    return render_template('ngo/opportunities.html', ngo=ngo, events=events)

@app.route('/volunteer/events/<int:event_id>')
def volunteer_event_detail(event_id: int):
    event = Event.query.get_or_404(event_id)
    ngo = NGO.query.get(event.ngo_id)
    time_slots = TimeSlot.query.filter_by(event_id=event.id, is_available=True).order_by(TimeSlot.start_time.asc()).all()
    return render_template('volunteer/event_detail.html', event=event, ngo=ngo, time_slots=time_slots)


# NGO Event Management Routes
@app.route('/ngo/events')
@login_required
def ngo_events():
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    events = Event.query.filter_by(ngo_id=ngo.id).order_by(Event.created_at.desc()).all()
    return render_template('ngo/events.html', events=events, ngo=ngo)

@app.route('/ngo/events/new', methods=['GET', 'POST'])
@login_required
def ngo_create_event():
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Parse required skills from form
            required_skills = request.form.getlist('required_skills')
            
            event = Event(
                ngo_id=ngo.id,
                title=request.form['title'],
                description=request.form['description'],
                location=request.form['location'],
                start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d'),
                end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d'),
                category=request.form['category'],
                max_volunteers=int(request.form['max_volunteers']),
                required_skills=json.dumps(required_skills),
                is_active=True
            )
            
            db.session.add(event)
            db.session.commit()
            
            # Create time slots for the event
            start_date = event.start_date
            end_date = event.end_date
            current_date = start_date
            
            while current_date <= end_date:
                # Create 2-hour slots from 9 AM to 5 PM
                for hour in range(9, 17, 2):
                    start_time = datetime.combine(current_date, datetime.min.time().replace(hour=hour))
                    end_time = start_time + timedelta(hours=2)
                    
                    time_slot = TimeSlot(
                        event_id=event.id,
                        start_time=start_time,
                        end_time=end_time,
                        max_volunteers=event.max_volunteers,
                        current_volunteers=0,
                        is_available=True
                    )
                    db.session.add(time_slot)
                
                current_date += timedelta(days=1)
            
            db.session.commit()
            flash('Event created successfully!', 'success')
            return redirect(url_for('ngo_events'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating event: {str(e)}', 'error')
    
    return render_template('ngo/create_event.html', ngo=ngo)

@app.route('/ngo/events/<int:event_id>')
@login_required
def ngo_view_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only view your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    time_slots = TimeSlot.query.filter_by(event_id=event.id).order_by(TimeSlot.start_time).all()
    bookings = Booking.query.filter_by(event_id=event.id).all()
    
    return render_template('ngo/view_event.html', event=event, time_slots=time_slots, bookings=bookings, ngo=ngo)

@app.route('/ngo/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def ngo_edit_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only edit your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    if request.method == 'POST':
        try:
            required_skills = request.form.getlist('required_skills')
            
            event.title = request.form['title']
            event.description = request.form['description']
            event.location = request.form['location']
            event.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
            event.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
            event.category = request.form['category']
            event.max_volunteers = int(request.form['max_volunteers'])
            event.required_skills = json.dumps(required_skills)
            event.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('ngo_view_event', event_id=event.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating event: {str(e)}', 'error')
    
    return render_template('ngo/edit_event.html', event=event, ngo=ngo)

@app.route('/ngo/events/<int:event_id>/delete', methods=['POST'])
@login_required
def ngo_delete_event(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only delete your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    try:
        # Delete related bookings and time slots first
        Booking.query.filter_by(event_id=event.id).delete()
        TimeSlot.query.filter_by(event_id=event.id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {str(e)}', 'error')
    
    return redirect(url_for('ngo_events'))

@app.route('/ngo/events/<int:event_id>/toggle-status', methods=['POST'])
@login_required
def ngo_toggle_event_status(event_id):
    if current_user.role != 'ngo':
        flash('Access denied. NGO access required.', 'error')
        return redirect(url_for('dashboard'))
    
    ngo = NGO.query.filter_by(user_id=current_user.id).first()
    if not ngo:
        flash('NGO profile not found.', 'error')
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    if event.ngo_id != ngo.id:
        flash('Access denied. You can only modify your own events.', 'error')
        return redirect(url_for('ngo_events'))
    
    try:
        event.is_active = not event.is_active
        db.session.commit()
        
        status = 'activated' if event.is_active else 'deactivated'
        flash(f'Event {status} successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating event status: {str(e)}', 'error')
    
    return redirect(url_for('ngo_view_event', event_id=event.id))

# API Routes
@app.route('/api/events')
def get_events():
    events = Event.query.filter_by(is_active=True).all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'start_date': event.start_date.isoformat(),
        'end_date': event.end_date.isoformat(),
        'ngo_name': NGO.query.get(event.ngo_id).organization_name
    } for event in events])

@app.route('/api/events/<int:event_id>/slots')
def get_event_slots(event_id):
    slots = TimeSlot.query.filter_by(event_id=event_id, is_available=True).all()
    return jsonify([{
        'id': slot.id,
        'start_time': slot.start_time.isoformat(),
        'end_time': slot.end_time.isoformat(),
        'available_spots': slot.max_volunteers - slot.current_volunteers
    } for slot in slots])

@app.route('/api/book-slot', methods=['POST'])
@login_required
def book_slot():
    if current_user.role != 'volunteer':
        return jsonify({'error': 'Only volunteers can book slots'}), 403
    
    try:
        data = request.json
        slot_id = data.get('slot_id')
        event_id = data.get('event_id')
        
        if not slot_id or not event_id:
            return jsonify({'error': 'Missing slot_id or event_id'}), 400
        
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        if not volunteer:
            return jsonify({'error': 'Volunteer profile not found'}), 400
        
        # Check if already booked
        existing_booking = Booking.query.filter_by(
            volunteer_id=volunteer.id,
            time_slot_id=slot_id
        ).first()
        
        if existing_booking:
            return jsonify({'error': 'You have already booked this slot'}), 400
        
        # Use database transaction to prevent race condition
        # Fix: Don't use nested transaction, use explicit commit/rollback
        slot = TimeSlot.query.with_for_update().get(slot_id)
        
        if not slot or not slot.is_available:
            return jsonify({'error': 'Slot not available'}), 400
        
        if slot.current_volunteers >= slot.max_volunteers:
            return jsonify({'error': 'Slot is full'}), 400
        
        # Create booking
        booking = Booking(
            volunteer_id=volunteer.id,
            time_slot_id=slot_id,
            event_id=event_id,
            status='confirmed'
        )
        
        # Update slot
        slot.current_volunteers += 1
        if slot.current_volunteers >= slot.max_volunteers:
            slot.is_available = False
        
        # Add booking to session and commit
        db.session.add(booking)
        db.session.commit()
        
        return jsonify({'message': 'Slot booked successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Booking failed: {str(e)}'}), 500

# Socket.IO events
@socketio.on('join_room')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'User has joined the room: {room}'}, room=room)

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    try:
        message = Message(
            sender_id=current_user.id,
            receiver_id=data['receiver_id'],
            content=data['message']
        )
        db.session.add(message)
        db.session.commit()
        
        emit('receive_message', {
            'sender': current_user.first_name + ' ' + current_user.last_name,
            'message': data['message'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=room)
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Failed to send message: {str(e)}'}, room=room)

# Search API Routes
@app.route('/api/search/ngos')
def search_ngos_api():
    """API endpoint for searching NGOs"""
    try:
        search_term = request.args.get('q', '')
        category = request.args.get('category', '') or None
        city = request.args.get('city', '') or None
        
        ngos = queries.search_ngos(search_term, category=category, city=city)
        
        return jsonify([{
            'id': ngo.id,
            'organization_name': ngo.organization_name,
            'description': ngo.description,
            'mission': ngo.mission,
            'category': ngo.category,
            'city': ngo.city,
            'state': ngo.state,
            'rating': getattr(ngo, 'rating', 0) or 0,
            'total_donations': getattr(ngo, 'total_donations', 0) or 0,
            'volunteers_count': getattr(ngo, 'volunteers_count', 0) or 0,
            'contact_email': ngo.email,
            'contact_phone': ngo.phone if hasattr(ngo, 'phone') else '',
            'website': ngo.website,
            'logo_url': ngo.logo or '',
            'is_verified': ngo.is_verified
        } for ngo in ngos])
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/search/events')
def search_events_api():
    """API endpoint for searching events"""
    try:
        search_term = request.args.get('q', '')
        category = request.args.get('category', '') or None
        location = request.args.get('location', '') or None
        
        events = queries.search_events(search_term, category=category, location=location)
        
        return jsonify([{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'location': event.location,
            'start_date': event.start_date.isoformat(),
            'end_date': event.end_date.isoformat(),
            'category': event.category,
            'max_volunteers': event.max_volunteers,
            'required_skills': json.loads(event.required_skills) if event.required_skills else [],
            'is_active': event.is_active,
            'ngo_id': event.ngo_id,
            'ngo_name': NGO.query.get(event.ngo_id).organization_name,
            'ngo_logo': NGO.query.get(event.ngo_id).logo_url or ''
        } for event in events])
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/ngos/categories')
def get_ngo_categories():
    """Get unique NGO categories"""
    try:
        categories = db.session.query(NGO.category).distinct().filter(
            NGO.category.isnot(None),
            NGO.is_verified == True
        ).order_by(NGO.category).all()
        
        return jsonify([cat[0] for cat in categories if cat[0]])
    except Exception as e:
        return jsonify({'error': f'Failed to get categories: {str(e)}'}), 500

@app.route('/api/events/categories')
def get_event_categories():
    """Get unique event categories"""
    try:
        categories = db.session.query(Event.category).distinct().filter(
            Event.category.isnot(None),
            Event.is_active == True
        ).order_by(Event.category).all()
        
        return jsonify([cat[0] for cat in categories if cat[0]])
    except Exception as e:
        return jsonify({'error': f'Failed to get categories: {str(e)}'}), 500

# Admin Dashboard Routes
@app.route('/admin/dashboard')
@admin_required
@rate_limit_admin_requests(max_requests=30, window_minutes=60)
def admin_dashboard():
    """Admin dashboard with overview statistics"""
    try:
        # Ensure current admin has full permissions so all buttons work
        ensure_super_admin(current_user)
        # Normalize time boundaries to datetimes (naive UTC)
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        start_of_today = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        start_of_month = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Get dashboard statistics
        stats = {
            'total_users': User.query.count(),
            'total_ngos': NGO.query.count(),
            'total_events': Event.query.count(),
            'total_donations': Donor.query.count(),
            'new_users_today': User.query.filter(
                User.created_at >= start_of_today
            ).count(),
            'pending_users': User.query.filter_by(is_verified=False).count(),
            'pending_ngos': NGO.query.filter_by(is_verified=False).count(),
            'events_this_week': Event.query.filter(
                Event.start_date >= now_utc,
                Event.start_date <= now_utc + timedelta(days=7)
            ).count(),
            'donations_this_month': Donor.query.filter(
                Donor.created_at >= start_of_month
            ).count(),
            'pending_reports': 0  # Will be implemented with reporting system
        }
        
        # Get recent admin activity
        recent_activity = AdminAuditLog.query.filter_by(
            admin_user_id=current_user.id
        ).order_by(AdminAuditLog.timestamp.desc()).limit(10).all()
        
        # Format activity data for template
        activity_data = []
        for activity in recent_activity:
            activity_data.append({
                'title': activity.action.replace('_', ' ').title(),
                'description': f"{activity.resource_type}: {activity.action}",
                'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M'),
                'success': activity.success,
                'icon': 'check-circle' if activity.success else 'exclamation-triangle'
            })
        
        # Get admin permissions
        admin_permissions = get_admin_permissions(current_user)
        
        # Log dashboard access
        log_admin_action(
            action='DASHBOARD_ACCESS',
            resource_type='ADMIN_DASHBOARD',
            success=True
        )
        
        return render_template('admin/dashboard.html', 
                             stats=stats, 
                             recent_activity=activity_data,
                             admin_permissions=admin_permissions)
    
    except Exception as e:
        log_admin_action(
            action='DASHBOARD_ACCESS_ERROR',
            resource_type='ADMIN_DASHBOARD',
            success=False,
            error_message=str(e)
        )
        flash(f'Error loading dashboard data: {str(e)}', 'error')
        # Add flag to avoid immediate redirect back to /admin/dashboard
        return redirect(url_for('index', no_admin_redirect='1'))

@app.route('/admin/users')
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=50, window_minutes=60)
def admin_users():
    """Admin user management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = User.query
        
        if search:
            query = query.filter(
                db.or_(
                    User.first_name.ilike(f'%{search}%'),
                    User.last_name.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        if status_filter:
            if status_filter == 'verified':
                query = query.filter(User.is_verified == True)
            elif status_filter == 'unverified':
                query = query.filter(User.is_verified == False)
            elif status_filter == 'active':
                query = query.filter(User.is_active == True)
            elif status_filter == 'inactive':
                query = query.filter(User.is_active == False)
        
        users = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_USERS_LIST',
            resource_type='USER_MANAGEMENT',
            success=True
        )
        
        return render_template('admin/users.html', users=users, 
                             search=search, role_filter=role_filter, 
                             status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_USERS_ERROR',
            resource_type='USER_MANAGEMENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading users', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def toggle_user_status(user_id):
    """Toggle user active status"""
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        
        action = 'ACTIVATE_USER' if user.is_active else 'DEACTIVATE_USER'
        log_admin_action(
            action=action,
            resource_type='USER',
            resource_id=user_id,
            details={'user_email': user.email, 'new_status': user.is_active}
        )
        
        if request.is_json:
            return jsonify({'success': True, 'message': f'User {action.lower().replace("_", " ")}d successfully'})
        else:
            flash(f'User {action.lower().replace("_", " ")}d successfully', 'success')
            return redirect(url_for('admin_users'))
    
    except Exception as e:
        log_admin_action(
            action='TOGGLE_USER_STATUS_ERROR',
            resource_type='USER',
            resource_id=user_id,
            success=False,
            error_message=str(e)
        )
        if request.is_json:
            return jsonify({'success': False, 'message': 'Error updating user status'}), 500
        else:
            flash('Error updating user status', 'error')
            return redirect(url_for('admin_users'))

@app.route('/admin/audit-logs/export')
@admin_required
@admin_permission_required('export_data')
def export_audit_logs():
    """Export audit logs to CSV"""
    app.logger.info(f"Export audit logs function called by user: {current_user.email}")
    
    try:
        import csv
        import io
        from datetime import datetime
        
        app.logger.info(f"Export audit logs started by user: {current_user.email}")
        
        # Get filtered logs
        admin_filter = request.args.get('admin', '')
        action_filter = request.args.get('action', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        app.logger.info(f"Filters - admin: {admin_filter}, action: {action_filter}, date_from: {date_from}, date_to: {date_to}")
        
        query = AdminAuditLog.query
        
        if admin_filter:
            query = query.filter_by(admin_id=admin_filter)
        if action_filter:
            query = query.filter_by(action=action_filter)
        if date_from:
            query = query.filter(AdminAuditLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            query = query.filter(AdminAuditLog.timestamp < datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        
        logs = query.all()
        app.logger.info(f"Found {len(logs)} audit logs to export")
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Admin Email', 'Admin Name', 'Action', 'Details', 'IP Address', 'User Agent'])
        
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.admin_user.email,
                f"{log.admin_user.first_name} {log.admin_user.last_name}",
                log.action,
                log.action_details or '',
                log.ip_address,
                log.user_agent
            ])
        
        # Create response
        output.seek(0)
        csv_content = output.getvalue()
        app.logger.info(f"Generated CSV with {len(csv_content)} characters")
        
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=audit_logs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        app.logger.info("Export completed successfully")
        return response
        
    except Exception as e:
        app.logger.error(f"Error exporting audit logs: {str(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error exporting audit logs: {str(e)}', 'error')
        return redirect(url_for('admin_audit_logs'))

@app.route('/admin/audit-logs/clear-old', methods=['POST'])
@admin_required
@admin_permission_required('manage_audit_logs')
def clear_old_audit_logs():
    """Clear audit logs older than 90 days"""
    try:
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=90)
        old_logs = AdminAuditLog.query.filter(AdminAuditLog.timestamp < cutoff_date).all()
        deleted_count = len(old_logs)
        
        for log in old_logs:
            db.session.delete(log)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} old audit logs'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/admin/settings')
@admin_required
@admin_permission_required('manage_settings')
def admin_settings():
    """Admin settings page"""
    try:
        # Get system settings
        settings = {
            'site_name': 'NGO Connect Platform',
            'site_email': 'admin@ngoconnect.com',
            'maintenance_mode': False,
            'registration_enabled': True,
            'email_verification_required': True,
            'max_login_attempts': 5,
            'session_timeout': 3600,
            'file_upload_max_size': 10 * 1024 * 1024,  # 10MB
            'allowed_file_types': ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx']
        }
        
        return render_template('admin/settings.html',
                             settings=settings,
                             admin_permissions=get_admin_permissions(current_user))
    except Exception as e:
        app.logger.error(f"Error loading admin settings: {str(e)}")
        flash('Error loading settings', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings/update', methods=['POST'])
@admin_required
@admin_permission_required('manage_settings')
def update_admin_settings():
    """Update admin settings"""
    try:
        # Get form data
        site_name = request.form.get('site_name')
        site_email = request.form.get('site_email')
        maintenance_mode = request.form.get('maintenance_mode') == 'on'
        registration_enabled = request.form.get('registration_enabled') == 'on'
        email_verification_required = request.form.get('email_verification_required') == 'on'
        max_login_attempts = int(request.form.get('max_login_attempts', 5))
        session_timeout = int(request.form.get('session_timeout', 3600))
        
        # Validate data
        if not site_name or not site_email:
            flash('Site name and email are required', 'error')
            return redirect(url_for('admin_settings'))
        
        # Here you would typically save to a settings table or config file
        # For now, we'll just log the changes
        app.logger.info(f"Admin settings updated by {current_user.email}: "
                       f"site_name={site_name}, maintenance_mode={maintenance_mode}, "
                       f"registration_enabled={registration_enabled}")
        
        log_admin_action(
            action='UPDATE_SETTINGS',
            resource_type='SETTINGS',
            details={'site_name': site_name, 'maintenance_mode': maintenance_mode}
        )
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin_settings'))
        
    except Exception as e:
        flash(f'Error updating settings: {str(e)}', 'error')
        return redirect(url_for('admin_settings'))

@app.route('/admin/users/<int:user_id>/verify', methods=['POST'])
@admin_required
@admin_permission_required('manage_users')
@rate_limit_admin_requests(max_requests=20, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def verify_user(user_id):
    """Verify a user account"""
    try:
        user = User.query.get_or_404(user_id)
        user.is_verified = True
        db.session.commit()
        
        log_admin_action(
            action='VERIFY_USER',
            resource_type='USER',
            resource_id=user_id,
            details={'user_email': user.email}
        )
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'User verified successfully'})
        else:
            flash('User verified successfully', 'success')
            return redirect(url_for('admin_users'))
    
    except Exception as e:
        log_admin_action(
            action='VERIFY_USER_ERROR',
            resource_type='USER',
            resource_id=user_id,
            success=False,
            error_message=str(e)
        )
        if request.is_json:
            return jsonify({'success': False, 'message': 'Error verifying user'}), 500
        else:
            flash('Error verifying user', 'error')
            return redirect(url_for('admin_users'))

@app.route('/admin/audit-logs')
@admin_required
@admin_permission_required('view_audit_logs')
def admin_audit_logs():
    """Admin audit logs page"""
    try:
        page = request.args.get('page', 1, type=int)
        admin_filter = request.args.get('admin', '')
        action_filter = request.args.get('action', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Build query
        query = AdminAuditLog.query
        
        if admin_filter:
            query = query.filter(AdminAuditLog.admin_user_id == admin_filter)
        
        if action_filter:
            query = query.filter(AdminAuditLog.action == action_filter)
        
        if date_from:
            query = query.filter(AdminAuditLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        
        if date_to:
            query = query.filter(AdminAuditLog.timestamp <= datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        
        logs = query.order_by(AdminAuditLog.timestamp.desc()).paginate(
            page=page, per_page=50, error_out=False
        )
        
        # Get unique actions for filter
        actions = db.session.query(AdminAuditLog.action).distinct().order_by(AdminAuditLog.action).all()
        actions = [action[0] for action in actions]
        
        # Get admin users for filter
        admin_users = User.query.filter_by(role='admin').all()
        
        log_admin_action(
            action='VIEW_AUDIT_LOGS',
            resource_type='AUDIT_LOG',
            success=True
        )
        
        return render_template('admin/audit_logs.html', logs=logs, actions=actions,
                             admin_users=admin_users, admin_filter=admin_filter,
                             action_filter=action_filter, date_from=date_from,
                             date_to=date_to)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_AUDIT_LOGS_ERROR',
            resource_type='AUDIT_LOG',
            success=False,
            error_message=str(e)
        )
        flash('Error loading audit logs', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/ngos')
@admin_required
@admin_permission_required('manage_ngos')
def admin_ngos():
    """Admin NGOs management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = NGO.query
        
        if search:
            query = query.filter(NGO.name.contains(search))
        
        if status_filter:
            query = query.filter(NGO.status == status_filter)
        
        ngos = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_NGOS',
            resource_type='NGO',
            success=True
        )
        
        return render_template('admin/ngos.html', ngos=ngos, search=search, status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_NGOS_ERROR',
            resource_type='NGO',
            success=False,
            error_message=str(e)
        )
        flash('Error loading NGOs', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/events')
@admin_required
@admin_permission_required('manage_events')
def admin_events():
    """Admin events management page"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = Event.query
        
        if search:
            query = query.filter(Event.title.contains(search))
        
        if status_filter:
            query = query.filter(Event.status == status_filter)
        
        events = query.paginate(page=page, per_page=20, error_out=False)
        
        log_admin_action(
            action='VIEW_EVENTS',
            resource_type='EVENT',
            success=True
        )
        
        return render_template('admin/events.html', events=events, search=search, status_filter=status_filter)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_EVENTS_ERROR',
            resource_type='EVENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading events', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/content')
@admin_required
@admin_permission_required('manage_content')
def admin_content():
    """Admin content management page"""
    try:
        log_admin_action(
            action='VIEW_CONTENT',
            resource_type='CONTENT',
            success=True
        )
        
        return render_template('admin/content.html')
    
    except Exception as e:
        log_admin_action(
            action='VIEW_CONTENT_ERROR',
            resource_type='CONTENT',
            success=False,
            error_message=str(e)
        )
        flash('Error loading content management', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/roles')
@admin_required
@admin_permission_required('manage_roles')
def admin_roles():
    """Admin role management page"""
    try:
        roles = AdminRole.query.all() 
        
        log_admin_action(
            action='VIEW_ROLES',
            resource_type='ROLE',
            success=True
        )
        
        return render_template('admin/roles.html', roles=roles)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_ROLES_ERROR',
            resource_type='ROLE',
            success=False,
            error_message=str(e)
        )
        flash('Error loading roles', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/profile')
@admin_required
def admin_profile():
    """Admin profile page"""
    try:
        log_admin_action(
            action='VIEW_PROFILE',
            resource_type='PROFILE',
            success=True
        )
        
        return render_template('admin/profile.html')
    
    except Exception as e:
        log_admin_action(
            action='VIEW_PROFILE_ERROR',
            resource_type='PROFILE',
            success=False,
            error_message=str(e)
        )
        flash('Error loading profile', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/analytics')
@admin_required
@admin_permission_required('view_analytics')
def admin_analytics():
    """Admin analytics dashboard"""
    try:
        # Get analytics data
        analytics_data = get_analytics_data()
        
        log_admin_action(
            action='VIEW_ANALYTICS',
            resource_type='ANALYTICS',
            success=True
        )
        
        return render_template('admin/analytics.html', analytics=analytics_data)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_ANALYTICS_ERROR',
            resource_type='ANALYTICS',
            success=False,
            error_message=str(e)
        )
        flash('Error loading analytics data', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/analytics/data')
@admin_required
@admin_permission_required('view_analytics')
def admin_analytics_data():
    """Get analytics data as JSON"""
    try:
        analytics_data = {
            'users': get_user_growth_data(),
            'ngo_categories': get_ngo_categories_data(),
            'event_types': get_event_types_data(),
            'donation_trends': get_donation_trends_data(),
            'user_roles_distribution': get_user_roles_distribution(),
            'platform_usage': get_platform_usage_data()
        }
        
        log_admin_action(
            action='VIEW_ANALYTICS_DATA',
            resource_type='ANALYTICS',
            success=True
        )
        
        return jsonify(analytics_data)
    
    except Exception as e:
        log_admin_action(
            action='VIEW_ANALYTICS_DATA_ERROR',
            resource_type='ANALYTICS',
            success=False,
            error_message=str(e)
        )
        return jsonify({'error': 'Failed to load analytics data'}), 500

# Analytics helper functions
def get_analytics_data():
    """Get analytics data for admin dashboard"""
    try:
        # Basic counts
        total_users = User.query.count()
        total_ngos = NGO.query.count()
        total_events = Event.query.count()
        # Donor model has no donation_amount column; use donor count as placeholder
        # Donors (unique) as placeholder for donations
        total_donations = db.session.query(db.func.count(db.func.distinct(Donor.user_id))).scalar() or 0
        
        # User growth (last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
        recent_users = User.query.filter(User.created_at >= thirty_days_ago).count()
        user_growth_rate = (recent_users / total_users * 100) if total_users > 0 else 0
        
        # Event participation rate
        total_volunteers = Volunteer.query.count()
        event_participation_rate = (total_volunteers / total_users * 100) if total_users > 0 else 0
        
        # Donation conversion rate
        donors = db.session.query(db.func.count(db.func.distinct(Donor.user_id))).scalar() or 0
        donation_conversion_rate = (donors / total_users * 100) if total_users > 0 else 0
        
        # Volunteer retention rate (simplified)
        volunteer_retention_rate = 85.0  # Placeholder
        
        # User roles distribution
        from sqlalchemy import func
        role_counts = db.session.query(User.role, func.count(User.id)).group_by(User.role).all()
        role_labels = [role.title() for role, _ in role_counts]
        role_data = [count for _, count in role_counts]
        
        # Registration trends (last 7 days)
        seven_days_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
        registration_data = []
        registration_labels = []
        for i in range(7):
            date = seven_days_ago + timedelta(days=i)
            next_date = date + timedelta(days=1)
            day_users = User.query.filter(User.created_at >= date, User.created_at < next_date).count()
            registration_data.append(day_users)
            registration_labels.append(date.strftime('%a'))
        
        # Activity data (last 7 days)
        login_activity = []
        event_activity = []
        donation_activity = []
        activity_labels = []
        
        for i in range(7):
            date = seven_days_ago + timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            # Logins (approximated by users with last_login in this period)
            day_logins = User.query.filter(User.last_login >= date, User.last_login < next_date).count()
            login_activity.append(day_logins)
            
            # Events created
            day_events = Event.query.filter(Event.created_at >= date, Event.created_at < next_date).count()
            event_activity.append(day_events)
            
            # Donations
            day_donations = Donor.query.filter(Donor.created_at >= date, Donor.created_at < next_date).count()
            donation_activity.append(day_donations)
            
            activity_labels.append(date.strftime('%a'))
        
        # Top NGOs by number of events and average planned volunteer capacity (no rating field on Event)
        from sqlalchemy import func
        top_ngos_raw = db.session.query(
            NGO.id,
            NGO.organization_name,
            func.count(Event.id).label('event_count'),
            func.avg(Event.max_volunteers).label('volunteer_capacity')
        ).join(Event, NGO.id == Event.ngo_id).group_by(NGO.id).order_by(func.desc('event_count')).limit(5).all()

        top_ngos = [
            {
                'id': r.id,
                'name': r.organization_name,
                'event_count': r.event_count,
                'volunteer_count': int(r.volunteer_capacity or 0),
            }
            for r in top_ngos_raw
        ]
        
        # Recent activities
        recent_activities = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).limit(10).all()
        activities = []
        for activity in recent_activities:
            activities.append({
                'description': f"{activity.action.replace('_', ' ').title()}",
                'user_name': f"{activity.admin.first_name} {activity.admin.last_name}",
                'timestamp': activity.timestamp,
                'icon': 'user' if 'user' in activity.action else 'cog' if 'setting' in activity.action else 'chart-bar'
            })
        
        return {
            'total_users': total_users,
            'total_ngos': total_ngos,
            'total_events': total_events,
            'total_donations': total_donations,
            'user_growth_rate': user_growth_rate,
            'event_participation_rate': event_participation_rate,
            'donation_conversion_rate': donation_conversion_rate,
            'volunteer_retention_rate': volunteer_retention_rate,
            'role_labels': role_labels,
            'role_data': role_data,
            'registration_labels': registration_labels,
            'registration_data': registration_data,
            'activity_labels': activity_labels,
            'login_activity': login_activity,
            'event_activity': event_activity,
            'donation_activity': donation_activity,
            'top_ngos': top_ngos,
            'recent_activities': activities
        }
    except Exception as e:
        app.logger.error(f"Error getting analytics data: {str(e)}")
        return {
            'total_users': 0,
            'total_ngos': 0,
            'total_events': 0,
            'total_donations': 0,
            'user_growth_rate': 0,
            'event_participation_rate': 0,
            'donation_conversion_rate': 0,
            'volunteer_retention_rate': 0,
            'role_labels': [],
            'role_data': [],
            'registration_labels': [],
            'registration_data': [],
            'activity_labels': [],
            'login_activity': [],
            'event_activity': [],
            'donation_activity': [],
            'top_ngos': [],
            'recent_activities': []
        }

def get_user_growth_data():
    """Get user growth data for charts"""
    from sqlalchemy import func
    
    # Get user registrations by month for the last 12 months
    user_data = db.session.query(
        func.date_format(User.created_at, '%Y-%m').label('month'),
        func.count(User.id).label('count')
    ).filter(
        User.created_at >= datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=365)
    ).group_by('month').order_by('month').all()
    
    return [{'month': item.month, 'count': item.count} for item in user_data]

def get_ngo_categories_data():
    """Get NGO categories distribution"""
    from sqlalchemy import func
    
    category_data = db.session.query(
        NGO.category,
        func.count(NGO.id).label('count')
    ).group_by(NGO.category).all()
    
    return [{'category': item.category or 'Unknown', 'count': item.count} for item in category_data]

def get_event_types_data():
    """Get event types distribution"""
    from sqlalchemy import func
    
    type_data = db.session.query(
        Event.category,
        func.count(Event.id).label('count')
    ).group_by(Event.category).all()
    
    return [{'type': item.category, 'count': item.count} for item in type_data]

def get_donation_trends_data():
    """Get donation trends data"""
    from sqlalchemy import func
    
    donation_data = db.session.query(
        func.date_format(Donor.created_at, '%Y-%m').label('month'),
        func.count(Donor.id).label('count')
    ).filter(
        Donor.created_at >= datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=365)
    ).group_by('month').order_by('month').all()
    
    return [{'month': item.month, 'count': item.count, 'total': 0.0} for item in donation_data]

def get_user_roles_distribution():
    """Get user roles distribution"""
    from sqlalchemy import func
    
    role_data = db.session.query(
        User.role,
        func.count(User.id).label('count')
    ).group_by(User.role).all()
    
    return [{'role': item.role, 'count': item.count} for item in role_data]

def get_platform_usage_data():
    """Get platform usage statistics"""
    return {
        'total_page_views': 0,  # Will implement with analytics
        'unique_visitors': User.query.filter(User.last_login >= (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30))).count(),
        'avg_session_duration': '15:30',  # Will implement with analytics
        'bounce_rate': '45%'  # Will implement with analytics
    }

# Additional admin routes
@app.route('/admin/users/<int:user_id>/delete', methods=['DELETE'])
@admin_required
@admin_permission_required('delete_users')
@rate_limit_admin_requests(max_requests=10, window_minutes=60)
@validate_admin_input({
    'user_id': {'type': 'integer', 'required': True}
})
def delete_user(user_id):
    """Delete a user"""
    try:
        user = User.query.get_or_404(user_id)
        if user.role == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin users'}), 400
            
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {user.email} has been deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/add-user', methods=['POST'])
@admin_required
@admin_permission_required('create_users')
@rate_limit_admin_requests(max_requests=15, window_minutes=60)
@validate_admin_input({
    'first_name': {'required': True, 'min_length': 1, 'max_length': 50, 'pattern': r'^[a-zA-Z\s]+$'},
    'last_name': {'required': True, 'min_length': 1, 'max_length': 50, 'pattern': r'^[a-zA-Z\s]+$'},
    'email': {'required': True, 'type': 'email', 'max_length': 120},
    'role': {'required': True, 'pattern': r'^(ngo|volunteer|donor)$'},
    'phone': {'max_length': 20, 'pattern': r'^\+?[\d\s\-\(\)]+$'}
})
def admin_add_user():
    """Create a new user"""
    try:
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        role = request.form.get('role')
        phone = request.form.get('phone')
        
        # Validate input
        if not all([first_name, last_name, email, role]):
            flash('All required fields must be filled', 'error')
            return redirect(url_for('admin_users'))
            
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'error')
            return redirect(url_for('admin_users'))
            
        # Generate random password
        import secrets
        import string
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        # Create new user
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,
            phone=phone,
            is_verified=True,
            is_active=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send welcome email with password (in production)
        flash(f'User created successfully. Temporary password: {password}', 'success')
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating user: {str(e)}', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/export')
@admin_required
@admin_permission_required('export_data')
def export_users():
    """Export users to CSV"""
    try:
        import csv
        import io
        from datetime import datetime
        
        # Get filtered users
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')
        
        query = User.query
        if search:
            query = query.filter(User.email.contains(search) | 
                               User.first_name.contains(search) | 
                               User.last_name.contains(search))
        if role_filter:
            query = query.filter_by(role=role_filter)
        if status_filter:
            if status_filter == 'verified':
                query = query.filter_by(is_verified=True)
            elif status_filter == 'unverified':
                query = query.filter_by(is_verified=False)
            elif status_filter == 'active':
                query = query.filter_by(is_active=True)
            elif status_filter == 'inactive':
                query = query.filter_by(is_active=False)
        
        users = query.all()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Email', 'First Name', 'Last Name', 'Role', 'Phone', 
                        'Verified', 'Active', 'Created At', 'Last Login'])
        
        for user in users:
            writer.writerow([
                user.id,
                user.email,
                user.first_name,
                user.last_name,
                user.role,
                user.phone or '',
                'Yes' if user.is_verified else 'No',
                'Yes' if user.is_active else 'No',
                user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never'
            ])
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting users: {str(e)}', 'error')
        return redirect(url_for('admin_users'))

if __name__ == '__main__':
    print("Starting NGO Connect Platform...")
    try:
        with app.app_context():
            db.create_all()
        print("Starting server on http://127.0.0.1:5000")
        # Use debug=False for production, debug=True for development
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        socketio.run(app, host='127.0.0.1', port=5000, debug=debug_mode)
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
