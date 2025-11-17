# wsgi.py
from app import app, init_database

# Ensure database/tables exist before gunicorn serves requests
try:
    init_database()
except Exception as e:
    # Log initialization errors to help debugging in production logs
    # Avoid crashing on import; log and let requests show errors if any
    import sys
    print("Warning: init_database() raised:", e, file=sys.stderr)

# Expose the WSGI callable for gunicorn
application = app
