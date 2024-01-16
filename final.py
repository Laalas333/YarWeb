from flask import Flask, render_template, request, jsonify, send_from_directory, session
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import yara
import secrets
import requests
import time
import hashlib
import json
from datetime import datetime
from flask import redirect, url_for
from flask import make_response
cache = {}
# Function to log cache to a file
def log_cache_to_file():
    with open('cache_log.json', 'w') as file:
        json.dump(cache, file, indent=4)
# Function to load cache from file
def load_cache_from_file():
    try:
        with open('cache_log.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}  # Return an empty cache if the file does not exist
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
with app.app_context():
    db.drop_all()  # Drops all tables
    db.create_all()  # Creates all tables

# Define a User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    logins = db.Column(db.Integer, default=0)
    last_login_at = db.Column(db.DateTime, default=None)
    total_time_spent = db.Column(db.Integer, default=0)  # Time spent in seconds

    def __repr__(self):
        return '<User %r>' % self.email

# Create the database tables
with app.app_context():
    db.create_all()

yara_directory = "yara_files"
os.makedirs(yara_directory, exist_ok=True)

@app.route('/')
def index():
    return render_template('demo.html')

@app.route('/demo.html')
def index_repeat():
    return render_template('demo.html')

@app.route('/login.html')
def login():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('page2'))
    response = make_response(render_template('login.html'))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.last_login_at:
            time_spent = (datetime.now() - user.last_login_at).seconds
            user.total_time_spent += time_spent
            db.session.commit()
    session.pop('logged_in', None)  # Clear the session
    return redirect(url_for('login'))

@app.route('/page2.html')
def page2():
    if 'logged_in' not in session or not session.get('logged_in'):
        return redirect(url_for('login'))
    response = make_response(render_template('page2.html'))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/index.html')
def index1():
    return render_template('index.html')

@app.route('/test.html')
def test():
    return render_template('test.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('reg-email')
    password = request.form.get('reg-password').encode('utf-8')
    confirm_password = request.form.get('reg-confirm-password')

    if password.decode('utf-8') != confirm_password:
        return "Passwords do not match. Please try again.", 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return "User already exists. Please login.", 409

    # Hashing the password
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/login', methods=['POST'])
def login_user():
    email = request.form.get('email')
    password = request.form.get('password')

    # Admin credentials (store these securely, for example in environment variables)
    admin_email = "admin@email.com"
    admin_password = "admin1234"

    # Check if user is admin
    if email == admin_email and password == admin_password:
        # If admin login is successful, set the admin session and redirect to dashboard
        session['logged_in'] = True
        session['is_admin'] = True
        return redirect(url_for('dashboard'))

    # Check for regular user login
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
        user.logins += 1
        user.last_login_at = datetime.now()
        db.session.commit()
        session['logged_in'] = True  # Set session variable
        session['user_id'] = user.id  # Store the user's id in the session
        return redirect(url_for('page2'))
    else:
        # Login failed
        return "Invalid credentials. Please try again.", 401


@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session and session['is_admin']:
        users = User.query.all()
        user_data = [{
            'username': user.email,
            'logins': user.logins,
            'time_spent': user.total_time_spent
        } for user in users]
        return render_template('dashboard.html', users=user_data)
    else:
        return redirect(url_for('login'))

@app.route('/update_yara_rule', methods=['POST'])
def update_yara_rule():
    if 'logged_in' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    signature = request.form.get('signature')
    string_file = request.files.get('string_file')

    if string_file and signature:
        new_content = string_file.read().decode('utf-8')
        yara_filename = os.path.join(yara_directory, f"{signature}.yara")

        with open(yara_filename, 'r+') as file:
            file_content = file.readlines()
            condition_line_index = next(i for i, line in enumerate(file_content) if line.strip().startswith('condition:'))

            # Calculate the indentation based on the existing condition line
            condition_indent = file_content[condition_line_index].find('condition:')
            indents = ' ' * condition_indent

            # Insert the new content with proper alignment (8 spaces)
            indented_new_content = ' ' * 8 + new_content.replace('\n', f'\n{indents}')
            file_content.insert(condition_line_index, indented_new_content + "\n")

            file.seek(0)  # Go back to the start of the file
            file.writelines(file_content)  # Write the modified content

        return redirect(url_for('dashboard'))  # Redirect back to the dashboard after updating

    return 'Error updating YARA rule', 400

@app.route('/page2')
def page2_view():
    return render_template('page2.html')

@app.route('/generate', methods=['POST'])
def generate_yara():
    malware_type = request.form.get('malwareType')
    csv_files = {
        "AgentTesla": "AgentTeslaDb.csv",
        "SnakeKeylogger": "SnakeKeyloggerDb.csv",
        "RedLineStealer": "RedLineStealerDb.csv",
        "Loki": "LokiDb.csv"
    }

    file_path = csv_files.get(malware_type, "default.csv")
    yara_rule = read_and_process_csv(file_path, malware_type)

    yara_filename = f"{malware_type}.yara"
    with open(os.path.join(yara_directory, yara_filename), 'w') as file:
        file.write(yara_rule)

    session['yara_filename'] = yara_filename  
    return jsonify({'filename': yara_filename})

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(yara_directory, filename, as_attachment=True)

def read_and_process_csv(file_path, malware_type):
    csv_data = pd.read_csv(file_path)

    def deduplicate_and_process_strings(strings):
        unique_strings = set()
        processed_strings = []
        counter = 0

        for string in strings:
            parts = string.split('$s')[1:]  
            for part in parts:
                string_start = part.find(' "')  
                if string_start != -1:
                    actual_string = part[string_start + 1:].strip()
                    if actual_string not in unique_strings:
                        unique_strings.add(actual_string)
                        processed_strings.append(f"$s{counter} = {actual_string}")
                        counter += 1

        return processed_strings

    deduplicated_processed_strings = deduplicate_and_process_strings(csv_data['Malicious_strings'])

    yara_rule = "rule MalwareDetection {\n"
    yara_rule += "    meta:\n"
    yara_rule += f"        description = \"Generic rule for {malware_type} .exe malwares\"\n"
    yara_rule += "        author = \"Group project\"\n"
    yara_rule += "    strings:\n"
    for s in deduplicated_processed_strings:
        yara_rule += f"        {s}\n"
    yara_rule += "    condition:\n"
    yara_rule += "         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )) or ( all of them )\n"
    yara_rule += "}"

    return yara_rule

def get_file_hash(file_content):
    return hashlib.sha256(file_content).hexdigest()

@app.route('/test_yara', methods=['POST'])
def test_yara():
    if 'exeFile' not in request.files:
        return 'No file uploaded', 400

    file = request.files['exeFile']
    if file.filename == '':
        return 'No file selected', 400

    file_content = file.read()
    file_hash = get_file_hash(file_content)

    # Check cache
    if file_hash in cache:
        return jsonify(cache[file_hash])

    filepath = os.path.join('temp', file.filename)
    with open(filepath, 'wb') as f:
        f.write(file_content)

    # YARA rule matching
    if 'yara_filename' not in session:
        os.remove(filepath)
        return 'YARA rule not generated', 400

    yara_rule_path = os.path.join(yara_directory, session['yara_filename'])
    try:
        rules = yara.compile(filepath=yara_rule_path)
        matches = rules.match(filepath)
        yara_result = 'Matched rules: ' + ', '.join([match.rule for match in matches]) if matches else 'No matches found'
    except Exception as e:
        os.remove(filepath)
        return f'Error testing YARA rule: {e}', 500

    # VirusTotal API integration
    vt_url = "https://www.virustotal.com/api/v3/files"
    api_key = "ee6945de582e9f49a6fdff39efc90f9b182c1a4c63e14e5163a93aef8ca339d7"

    with open(filepath, 'rb') as f:
        files = {'file': (file.filename, f)}
        headers = {'x-apikey': api_key}
        response = requests.post(vt_url, files=files, headers=headers)

    if response.status_code == 200:
        data = response.json()
        analysis_id = data['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Wait for a few seconds before requesting the results
        time.sleep(15)

        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code == 200:
            analysis_data = analysis_response.json()
            os.remove(filepath)  # Clean up the uploaded file after getting the results
            cache_result = {'yara_result': yara_result, 'vt_data': analysis_data}
            cache[file_hash] = cache_result  # Store result in cache
            log_cache_to_file()  # Log cache to file
            return jsonify(cache_result)
        else:
            os.remove(filepath)  # Clean up the uploaded file in case of error
            cache_result = {'yara_result': yara_result, 'vt_data': 'Error retrieving analysis results'}
            cache[file_hash] = cache_result
            return jsonify(cache_result)
    else:
        os.remove(filepath)  # Clean up the uploaded file in case of error
        cache_result = {'yara_result': yara_result, 'vt_data': 'Error submitting file to VirusTotal'}
        cache[file_hash] = cache_result
        return jsonify(cache_result)

if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.run(host='localhost', port=5000, debug=True)
