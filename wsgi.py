# wsgi.py
import sys, traceback, os, time

# short, obvious log messages so Railway shows import progress
print("wsgi.py: import started", file=sys.stderr)
sys.stderr.flush()
time.sleep(0.1)

try:
    # import the app and init function from your Flask file
    from app import app, init_database
    print("wsgi.py: imported app and init_database successfully", file=sys.stderr)
    sys.stderr.flush()
except Exception as e:
    print("wsgi.py: FAILED to import app or init_database", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    # re-raise so gunicorn fails loudly (you'll see full traceback)
    raise
# Attempt to initialize DB and log any exceptions
try:
    print("wsgi.py: calling init_database()", file=sys.stderr)
    sys.stderr.flush()
    init_database()
    print("wsgi.py: init_database() completed", file=sys.stderr)
    sys.stderr.flush()
except Exception:
    print("wsgi.py: init_database() raised an exception", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    # keep running — we want to see runtime errors too, so do not exit here

# Expose application for gunicorn
application = app

print("wsgi.py: done. application ready", file=sys.stderr)
sys.stderr.flush()
