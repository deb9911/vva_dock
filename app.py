import subprocess
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets, os, time, threading, shutil, requests
import zipfile, json

# Generate a secure secret key for the Flask app
secure_key = secrets.token_hex(16)

app = Flask(__name__)
app.secret_key = secure_key  # Necessary for session management
app.config['SECRET_KEY'] = secure_key
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Options: 'Lax', 'Strict', or 'None'
app.config['SESSION_COOKIE_SECURE'] = True     # Use True only if using HTTPS
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize variables to store search status and log directory
SEARCH_STATUS = {'progress': 0, 'status': 'Searching...', 'found': False}
LOG_DIRECTORY = None

# Directories to search (you can add/remove directories as needed)
# Dynamically fetch the user's home directory
user_home_dir = os.path.expanduser("~")

# Update the search directories to be relative to the user's home directory
SEARCH_DIRECTORIES = [
    os.path.join(user_home_dir, ''),       # User's home directory
    os.path.join(user_home_dir, 'Documents'),  # Common directory for documents
    os.path.join(user_home_dir, 'Downloads'),  # Common directory for downloads
    os.path.join(user_home_dir, 'Desktop'),    # Common directory for desktop items
]

# Lock for thread safety
search_lock = threading.Lock()
# Initialize database (run once to create tables)
with app.app_context():
    db.create_all()


@app.route('/test_session')
def test_session():
    session['test'] = 'This is a test'
    return 'Session set'


@app.route('/get_session')
def get_session():
    return session.get('test', 'Session not found')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """Hashes the password and stores it in the password_hash field."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks the hashed password."""
        return check_password_hash(self.password_hash, password)


# Form class for registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


# Form class for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Update authenticate function to query the database
def authenticate(username, password):
    user = User.query.filter_by(email=username).first()
    return user and user.check_password(password)


@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            session['logged_in'] = True
            session['email'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('User not found. Please log in again.', 'danger')
    return render_template('login.html')



# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     print("Form data:", request.form)
#     print("Session data after login:", session)
#     if request.method == 'POST':
#         session['logged_in'] = True
#         session['email'] = 'test@example.com'
#         flash('Login successful!', 'success')
#         return redirect(url_for('home'))
#     return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ======================
# REGISTRATION (Future)
# ======================

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password and save the user
        new_user = User(email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)



# ======================
# PROTECTING ROUTES
# ======================


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("You need to log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function




# Route for initial page
@app.route('/')
@login_required
def index():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('home'))
    return render_template('base.html')


@app.route('/home')
@login_required
def home():
    # Define paths using the user's home directory
    user_home_dir = os.path.expanduser("~")
    base_dir = os.path.join(user_home_dir, 'Vaani Virtual Assistant')
    query_list_path = os.path.join(base_dir, 'query_list', 'cmd.json')
    commands = []

    # Check if base directory and cmd.json exist
    if os.path.exists(base_dir) and os.path.exists(query_list_path):
        try:
            with open(query_list_path, 'r') as file:
                data = json.load(file)
                # Iterate over all lists in the JSON and aggregate commands
                for key, cmd_list in data.items():
                    if isinstance(cmd_list, list):
                        commands.extend(cmd_list)
        except json.JSONDecodeError:
            flash('Error decoding cmd.json file', 'danger')
        except Exception as e:
            flash(f'Error loading commands: {str(e)}', 'danger')
    print(f'commands\t::\t{commands}')
    print("Accessing home - logged in:", session.get('logged_in'))
    return render_template('home.html', user_name="John Doe", user_email=session.get('email'),
                           user_profile_image="profile.jpg", app_name="My Flask App",
                           app_version="1.0", app_status="Running", last_updated="2024-09-18",
                           # commands=["Command 1", "Command 2", "Command 3"],
                           commands=commands,
                           recent_activities=["Logged in", "Updated settings"])


def search_system_for_directory(directory_name):
    global SEARCH_STATUS, LOG_DIRECTORY

    with search_lock:
        SEARCH_STATUS = {'progress': 0, 'status': 'Searching...', 'found': False}
        LOG_DIRECTORY = None
        total_dirs = len(SEARCH_DIRECTORIES)
        processed_dirs = 0

    for search_dir in SEARCH_DIRECTORIES:
        if SEARCH_STATUS['found']:
            break

        processed_dirs += 1
        with search_lock:
            SEARCH_STATUS['progress'] = int((processed_dirs / total_dirs) * 100)
            SEARCH_STATUS['status'] = f"Searching in: {search_dir}"

        try:
            for root, dirs, _ in os.walk(search_dir):
                with search_lock:
                    SEARCH_STATUS['status'] = f"Searching in: {root}"
                for dir_name in dirs:
                    if dir_name == directory_name:
                        potential_path = os.path.join(root, dir_name)
                        if os.path.exists(potential_path):
                            with search_lock:
                                LOG_DIRECTORY = potential_path
                                SEARCH_STATUS['status'] = f"Found: {potential_path}"
                                SEARCH_STATUS['found'] = True
                            return
                time.sleep(0.01)  # Simulate search delay for better progress visualization
        except Exception as e:
            with search_lock:
                SEARCH_STATUS['status'] = f"Error while searching in: {search_dir} - {str(e)}"

    with search_lock:
        SEARCH_STATUS['progress'] = 100
        if not SEARCH_STATUS['found']:
            SEARCH_STATUS['status'] = "No directory found with the specified name."


# Route for debugging
@app.route('/control_panel')
@login_required
def control_panel():
    return render_template('control_panel.html')


@app.route('/debug')
@login_required
def debug():
    # Render the existing debugging functionalities
    return render_template('debug.html')


@app.route('/control_center')
@login_required
def control_center():
    return render_template('control_center.html')


# Global variable to store console output
console_output = []


def run_application():
    global current_process
    try:
        # Get the user's home directory
        home_directory = os.path.expanduser("~")

        # Define the path to the .exe file
        exe_file_path = os.path.join(home_directory, "Vaani Virtual Assistant", "main_new.exe")

        # Ensure the exe file exists before running
        if not os.path.exists(exe_file_path):
            print(f"Error: {exe_file_path} does not exist.")
            return

        # Run the .exe file in a new console window, with the correct working directory
        current_process = subprocess.Popen(
            [exe_file_path],
            cwd=os.path.join(home_directory, "Vaani Virtual Assistant"),  # Set working directory
            creationflags=subprocess.CREATE_NEW_CONSOLE  # Create a new console window
        )

        # Wait for the process to complete (optional)
        current_process.wait()

    except Exception as e:
        print(f"Error starting application: {e}")


# Flask route to start the application
@app.route('/start_application', methods=['POST'])
def start_application():
    # Start the application in a new thread
    thread = threading.Thread(target=run_application)
    thread.start()

    return jsonify({'status': 'success', 'message': 'Application started in a new console window.'})


# Route to get the console output
@app.route('/get_console_output', methods=['GET'])
@login_required
def get_console_output():
    global console_output
    return jsonify({'console_output': console_output})


# Route to handle the "Kill" button (optional)
@app.route('/kill_application', methods=['POST'])
@login_required
def kill_application():
    # Logic for killing the process (if applicable)
    return jsonify({'status': 'success', 'message': 'Application terminated.'})


# Route to start a background search
@app.route('/start_search', methods=['POST'])
@login_required
def start_search():
    with search_lock:
        SEARCH_STATUS['progress'] = 0
        SEARCH_STATUS['status'] = 'Searching...'
        SEARCH_STATUS['found'] = False
        LOG_DIRECTORY = None

    # search_thread = threading.Thread(target=search_system_for_directory, args=("Vani_Virtual-Assistant_pre_llm",))
    search_thread = threading.Thread(target=search_system_for_directory, args=("Vaani Virtual Assistant",))
    search_thread.start()

    return jsonify({'message': 'Search started'})


# Route to fetch search status
@app.route('/search_status')
@login_required
def search_status():
    return jsonify(SEARCH_STATUS)


# Route to fetch log files
@app.route('/fetch_log_files')
@login_required
def fetch_log_files():
    if LOG_DIRECTORY and os.path.exists(LOG_DIRECTORY):
        log_files = [{'name': f, 'path': os.path.join(LOG_DIRECTORY, f)}
                     for f in os.listdir(LOG_DIRECTORY) if f.startswith('vani_assistant_log') and f.endswith('.log')]
        return jsonify(log_files)
    else:
        return jsonify([])


# Route to read a specific log file
@app.route('/read_log_file')
@login_required
def read_log_file():
    log_file_path = request.args.get('path')
    if log_file_path and os.path.isfile(log_file_path):
        with open(log_file_path, 'r') as file:
            content = file.read()
        return content
    return 'File not found or not accessible.', 404


# Recursive function to fetch the file structure
def get_file_structure(directory):
    structure = []
    try:
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path):
                structure.append({
                    'name': item,
                    'path': item_path,
                    'type': 'directory',
                    'children': get_file_structure(item_path)
                })
            else:
                structure.append({
                    'name': item,
                    'path': item_path,
                    'type': 'file'
                })
    except PermissionError:
        pass  # Skip directories/files that cannot be accessed
    return structure


# Route to fetch file structure of a directory
@app.route('/fetch_file_structure')
@login_required
def fetch_file_structure():
    if LOG_DIRECTORY and os.path.exists(LOG_DIRECTORY):
        file_structure = get_file_structure(LOG_DIRECTORY)
        return jsonify(file_structure)
    else:
        return jsonify([])


@app.route('/package_management')
@login_required
def package_management():
    home_directory = os.path.expanduser("~")
    vaani_directory = os.path.join(home_directory, "Vaani Virtual Assistant")

    # Check if the package path exists
    setup_complete = os.path.exists(vaani_directory) and os.path.exists(os.path.join(vaani_directory, 'main_new.exe'))
    package_path = vaani_directory if setup_complete else None

    # Update the session for frontend access
    session['setup_complete'] = setup_complete
    session['package_path'] = package_path

    return render_template('package_management.html', setup_complete=setup_complete,
                           package_path=package_path)


@app.route('/download_package', methods=['POST'])
@login_required
def download_package():
    zip_file_url = "https://github.com/deb9911/VVA_pre_llm/releases/download/v1/pilot_pkg.zip"
    home_directory = os.path.expanduser("~")
    vaani_directory = os.path.join(home_directory, "Vaani Virtual Assistant")
    zip_file_path = os.path.join(vaani_directory, 'package.zip')

    # Ensure the 'Vaani Virtual Assistant' directory exists
    if not os.path.exists(vaani_directory):
        os.makedirs(vaani_directory)

    # Step 1: Download the zip file
    try:
        session['progress'] = 0
        with requests.get(zip_file_url, stream=True) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0

            with open(zip_file_path, 'wb') as zip_file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        zip_file.write(chunk)
                        downloaded_size += len(chunk)
                        session['progress'] = int((downloaded_size / total_size) * 100)
    except requests.exceptions.RequestException as e:
        return jsonify({'status': 'error', 'message': f"Failed to download zip file: {str(e)}"}), 500

    # Step 2: Extract the zip file
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(vaani_directory)

        # Step 3: Organize files into directories
        log_directory = os.path.join(vaani_directory, "log")
        query_directory = os.path.join(vaani_directory, "query_list")
        os.makedirs(log_directory, exist_ok=True)
        os.makedirs(query_directory, exist_ok=True)

        # Move cmd.json to query_list directory
        cmd_json = next((f for f in zip_ref.namelist() if 'cmd.json' in f), None)
        if cmd_json:
            shutil.move(os.path.join(vaani_directory, cmd_json), os.path.join(query_directory, 'cmd.json'))
        else:
            return jsonify({'status': 'error', 'message': 'cmd.json not found in the zip file'}), 500

        # Move main_new.exe to the vaani_directory (main directory)
        main_exe = next((f for f in zip_ref.namelist() if 'main_new.exe' in f), None)
        if main_exe:
            shutil.move(os.path.join(vaani_directory, main_exe), os.path.join(vaani_directory, 'main_new.exe'))
        else:
            return jsonify({'status': 'error', 'message': 'main_new.exe not found in the zip file'}), 500

        # Remove the extracted 'dist' directory if it exists
        dist_directory = os.path.join(vaani_directory, 'dist')
        if os.path.exists(dist_directory):
            shutil.rmtree(dist_directory)

    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to extract or organize files: {str(e)}"}), 500

    # Step 4: Delete the zip file after extraction
    try:
        os.remove(zip_file_path)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to delete zip file: {str(e)}"}), 500

    session['progress'] = 100
    return jsonify({'status': 'success', 'message': 'Package downloaded, extracted, and organized successfully.',
                    'package_path': vaani_directory})


@app.route('/progress', methods=['GET'])
@login_required
def get_progress():
    progress = session.get('progress', 0)
    return jsonify({'progress': progress})


# Route for settings page
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


# Route to add a new tab
@app.route('/add_tab', methods=['GET', 'POST'])
@login_required
def add_tab():
    if request.method == 'POST':
        tab_name = request.form['tab_name']
        # Add logic to create a new tab and update the navigation bar
        flash(f"New tab '{tab_name}' added!", "success")
        return redirect(url_for('home'))
    else:
        return render_template('add_tab.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    # app.run(debug=True)
    # app.run(host='127.0.0.1', debug=True)


