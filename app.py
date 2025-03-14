from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# ✅ Ensure we write to the correct Nginx config file
NGINX_CONFIG_PATH = "/etc/nginx/conf.d/reverse_proxy.conf"

NGINX_TEMPLATE = """
server {{
    listen 80;
    server_name api.garden.finance;
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name api.garden.finance;

    ssl_certificate /etc/letsencrypt/live/api.garden.finance/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.garden.finance/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;


    # Serve the custom page at the root path
    location / {{
        root /var/www/html;
        index index.nginx-debian.html;
        try_files $uri $uri/ =404;
    }}
{locations}
}}
"""

# Location block with proper SSL proxying
LOCATION_TEMPLATE = """
    location /{service_name}/ {{
        rewrite ^/{service_name}/(.*)$ /$1 break;
        proxy_pass {protocol}://{backend_service}/;  # Use the protocol here
        proxy_ssl_server_name on;  # 🔥 Enables SNI
        proxy_ssl_protocols TLSv1.2 TLSv1.3;  # 🔥 Uses modern TLS
        proxy_ssl_verify off;  # (Optional: Disable SSL verification if necessary)
        proxy_set_header Host {backend_service};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
"""

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# SQLite database setup
DATABASE = 'nginx_mappings.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL UNIQUE,
                backend_service TEXT NOT NULL,
                backend_port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'http',  
                enabled BOOLEAN NOT NULL DEFAULT 1
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')

        # Check if the default user exists
        default_user = conn.execute('SELECT id FROM users WHERE username = ?', ('user',)).fetchone()
        if not default_user:
            # Create the default user with hashed password
            hashed_password = generate_password_hash('admin')
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user', hashed_password))
            conn.commit()

init_db()

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute('SELECT id, password FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user[1], password):
                user_obj = User(user[0])
                login_user(user_obj)
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    with sqlite3.connect(DATABASE) as conn:
        mappings = conn.execute('SELECT * FROM mappings').fetchall()
    return render_template('index.html', mappings=mappings)

@app.route('/add_mapping', methods=['POST'])
@login_required
def add_mapping():
    data = request.json
    service_name = data.get('service_name')
    backend_service = data.get('backend_service')
    backend_port = data.get('backend_port')
    protocol = data.get('protocol', 'http')  # Default to 'http' if not provided

    if not service_name or not backend_service or not backend_port:
        return jsonify({'error': 'Missing required fields'}), 400

    with sqlite3.connect(DATABASE) as conn:
        try:
            conn.execute('INSERT INTO mappings (service_name, backend_service, backend_port, protocol) VALUES (?, ?, ?, ?)',
                         (service_name, backend_service, backend_port, protocol))
            conn.commit()
            update_nginx_config()
            return jsonify({'message': 'Mapping added successfully'})
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Service name already exists'}), 400

@app.route('/delete_mapping/<int:mapping_id>', methods=['POST'])
@login_required
def delete_mapping(mapping_id):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DELETE FROM mappings WHERE id = ?', (mapping_id,))
        conn.commit()
        update_nginx_config()
    return jsonify({'message': 'Mapping deleted successfully'})

@app.route('/toggle_mapping/<int:mapping_id>', methods=['POST'])
@login_required
def toggle_mapping(mapping_id):
    with sqlite3.connect(DATABASE) as conn:
        mapping = conn.execute('SELECT enabled FROM mappings WHERE id = ?', (mapping_id,)).fetchone()
        new_status = not mapping[0]
        conn.execute('UPDATE mappings SET enabled = ? WHERE id = ?', (new_status, mapping_id))
        conn.commit()
        update_nginx_config()
    return jsonify({'message': 'Mapping toggled successfully', 'enabled': new_status})

from flask import render_template_string

def update_nginx_config():
    print("Creating Config")
    with sqlite3.connect(DATABASE) as conn:
        mappings = conn.execute('SELECT * FROM mappings WHERE enabled = 1').fetchall()

    locations = "\n".join(
        LOCATION_TEMPLATE.format(
            service_name=mapping[1],
            backend_service=f"{mapping[2]}:{mapping[3]}",
            protocol=mapping[4]  # Use the protocol from the database
        )
        for mapping in mappings
    )

    config_content = NGINX_TEMPLATE.format(locations=locations)

    os.makedirs(os.path.dirname(NGINX_CONFIG_PATH), exist_ok=True)

    with open(NGINX_CONFIG_PATH, 'w') as f:
        f.write(config_content)

    # Prepare mapping data for template rendering
    mapping_data = [
        {
            "service_name": mapping[1],
            "backend_service": mapping[2],
            "backend_port": mapping[3],
            "protocol": mapping[4]
        }
        for mapping in mappings
    ]

    # Read template file
    template_path = os.path.join(os.path.dirname(__file__), "templates/mapping.html")
    with open(template_path, "r") as template_file:
        template_content = template_file.read()

    # Render the template inside Flask's application context
    with app.app_context():
        html_output = render_template_string(template_content, mappings=mapping_data)

    # Write the rendered HTML to /var/www/html/index.nginx-debian.html
    html_path = "/var/www/html/index.nginx-debian.html"
    with open(html_path, "w") as html_file:
        html_file.write(html_output)

    try:
        subprocess.run(['nginx', '-t'], check=True)
        subprocess.run(['nginx', '-s', 'reload'], check=True)
    except subprocess.CalledProcessError as e:
        print(f'Error reloading Nginx: {e}')

update_nginx_config()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
