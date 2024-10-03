from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import secrets, os, time, threading, shutil, requests

# Generate a secure secret key for the Flask app
secure_key = secrets.token_hex(16)

app = Flask(__name__)
app.secret_key = secure_key  # Necessary for session management

# Initialize variables to store search status and log directory
SEARCH_STATUS = {'progress': 0, 'status': 'Searching...', 'found': False}
LOG_DIRECTORY = None

# Directories to search (you can add/remove directories as needed)
SEARCH_DIRECTORIES = [
    '/home',  # User home directories
    '/usr/local',  # Common location for user-installed software
    '/opt',  # Optional application software packages
    '/var/log',  # System logs (if needed)
]

# A simple user store with emails and passwords
USERS = {
    'user@example.com': 'password123'
}

# Lock for thread safety
search_lock = threading.Lock()

# Authentication function
def authenticate(username, password):
    """
    Function to authenticate user credentials.
    :param username: str - User's email
    :param password: str - User's password
    :return: True if authenticated, else False
    """
    return USERS.get(username) == password

# Route to test static page rendering
@app.route('/static_test')
def static_test():
    return render_template('static_test.html')

# Route for initial page
@app.route('/')
def index():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('home'))
    return render_template('base.html')

# Route for login functionality
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle login request
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            session['logged_in'] = True
            session['email'] = username
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials, please try again.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

# Route for home page (only accessible if logged in)
@app.route('/home')
def home():
    # Check if the user is logged in
    # if 'logged_in' not in session or not session['logged_in']:
    #     flash("You are not logged in.", "warning")
    #     return redirect(url_for('index'))

    return render_template('home.html', user_name="John Doe", user_email=session.get('email'),
                           user_profile_image="profile.jpg", app_name="My Flask App",
                           app_version="1.0", app_status="Running", last_updated="2024-09-18",
                           commands=["Command 1", "Command 2", "Command 3"],
                           recent_activities=["Logged in", "Updated settings"])

# Route to log out
@app.route('/logout')
def logout():
    # Handle logout request
    session.pop('logged_in', None)
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Background search function
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
                        potential_path = os.path.join(root, dir_name, 'dist')
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
@app.route('/debugging')
def debugging():
    return render_template('debugging.html')

# Route to start a background search
@app.route('/start_search', methods=['POST'])
def start_search():
    with search_lock:
        SEARCH_STATUS['progress'] = 0
        SEARCH_STATUS['status'] = 'Searching...'
        SEARCH_STATUS['found'] = False
        LOG_DIRECTORY = None

    search_thread = threading.Thread(target=search_system_for_directory, args=("Vani_Virtual-Assistant_pre_llm",))
    search_thread.start()

    return jsonify({'message': 'Search started'})

# Route to fetch search status
@app.route('/search_status')
def search_status():
    return jsonify(SEARCH_STATUS)

# Route to fetch log files
@app.route('/fetch_log_files')
def fetch_log_files():
    if LOG_DIRECTORY and os.path.exists(LOG_DIRECTORY):
        log_files = [{'name': f, 'path': os.path.join(LOG_DIRECTORY, f)}
                     for f in os.listdir(LOG_DIRECTORY) if f.startswith('vani_assistant_log') and f.endswith('.log')]
        return jsonify(log_files)
    else:
        return jsonify([])

# Route to read a specific log file
@app.route('/read_log_file')
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
def fetch_file_structure():
    if LOG_DIRECTORY and os.path.exists(LOG_DIRECTORY):
        file_structure = get_file_structure(LOG_DIRECTORY)
        return jsonify(file_structure)
    else:
        return jsonify([])


@app.route('/package_management')
def package_management():
    setup_complete = session.get('setup_complete', False)
    package_path = session.get('package_path', None)

    return render_template('package_management.html', setup_complete=setup_complete, package_path=package_path)


@app.route('/download_package', methods=['POST'])
def download_package():
    # Step 1: Define the package URLs
    package_url = "https://1drv.ms/u/s!AqkAgHILBnzzg95Gc0gvj3gtP1Mt9w?e=uq9adq"
    package_name = "Setup.exe"
    cmd_json_url = "https://1drv.ms/u/s!AqkAgHILBnzzg95HI_6u1Al_jKsqqg?e=o1fRaw"
    cmd_json_name = "cmd.json"

    # Step 2: Determine the user's home directory and create 'Vaani Virtual Assistant' folder
    home_directory = os.path.expanduser("~")
    vaani_directory = os.path.join(home_directory, "Vaani Virtual Assistant")

    if not os.path.exists(vaani_directory):
        os.makedirs(vaani_directory)

    # Step 3: Download the package (.exe file)
    package_path = os.path.join(vaani_directory, package_name)
    try:
        response = requests.get(package_url, stream=True)
        with open(package_path, 'wb') as package_file:
            shutil.copyfileobj(response.raw, package_file)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to download package: {str(e)}"}), 500

    # Step 4: Create 'query_list' directory (no log directory)
    query_directory = os.path.join(vaani_directory, "query_list")

    try:
        if not os.path.exists(query_directory):
            os.makedirs(query_directory)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to create query_list directory: {str(e)}"}), 500

    # Step 5: Download the cmd.json file and place it in the query_list directory
    cmd_json_path = os.path.join(query_directory, cmd_json_name)
    try:
        cmd_response = requests.get(cmd_json_url, stream=True)
        with open(cmd_json_path, 'wb') as cmd_file:
            shutil.copyfileobj(cmd_response.raw, cmd_file)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to download cmd.json: {str(e)}"}), 500

    # Step 6: Store the information in the session
    session['setup_complete'] = True
    session['package_path'] = package_path
    session['query_directory'] = query_directory

    # Step 7: Return success and file path details (only for Setup.exe)
    return jsonify({
        'status': 'success',
        'message': 'Package downloaded successfully.',
        'package_path': package_path
    })


# Route for settings page
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Route to add a new tab
@app.route('/add_tab', methods=['GET', 'POST'])
def add_tab():
    if request.method == 'POST':
        tab_name = request.form['tab_name']
        # Add logic to create a new tab and update the navigation bar
        flash(f"New tab '{tab_name}' added!", "success")
        return redirect(url_for('home'))
    else:
        return render_template('add_tab.html')


if __name__ == '__main__':
    # app.run(debug=True, host='192.168.56.1', port=5000, threaded=True)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    # app.run(debug=True)
    # app.run(host='127.0.0.1', debug=True)


