import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-change-in-production'
    # Database Configuration
    if os.environ.get('DATABASE_URL'):
        # Generic Production URI (e.g., Render, Heroku)
        uri = os.environ.get('DATABASE_URL')
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = uri
    elif os.environ.get('PYTHONANYWHERE_DOMAIN'):
        # Specific for PythonAnywhere
        # Using SQLite since MySQL is not available on some free accounts
        basedir = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'internship_portal.db')
    else:
        # Development (Local MySQL via XAMPP)
        MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'
        MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or ''
        MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
        MYSQL_DB = os.environ.get('MYSQL_DB') or 'internship_portal_db'
        SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Mail Config (Example - needs real SMTP server in production)
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER')
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS')
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

    # Session Stability
    SESSION_PERMANENT = True
    REMEMBER_COOKIE_DURATION = 3600 * 24 * 7 # 1 week
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False
    
    # Upload folder
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
