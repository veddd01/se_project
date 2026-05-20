import sys
import traceback
import time

print("wsgi.py: import started", file=sys.stderr)
sys.stderr.flush()
time.sleep(0.1)

try:
    from app import app, init_database

    print(
        "wsgi.py: imported app and init_database successfully",
        file=sys.stderr
    )
    sys.stderr.flush()

except Exception:
    print(
        "wsgi.py: FAILED to import app or init_database",
        file=sys.stderr
    )

    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    raise


# Initialize database
try:
    print("wsgi.py: calling init_database()", file=sys.stderr)
    sys.stderr.flush()

    init_database()

    print("wsgi.py: init_database() completed", file=sys.stderr)
    sys.stderr.flush()

except Exception:
    print(
        "wsgi.py: init_database() raised an exception",
        file=sys.stderr
    )

    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()


# Expose Flask app
application = app

print("wsgi.py: done. application ready", file=sys.stderr)
sys.stderr.flush()
