from flask import Flask, render_template, jsonify, request
import sqlite3
import traceback
import sys
import os

app = Flask(__name__)

# Use writable temp directory on Vercel
DB_NAME = "/tmp/creative_registry.db"


def init_database():
    """Initialize database tables if they don't exist"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator TEXT NOT NULL,
            title TEXT NOT NULL,
            work_type TEXT NOT NULL,
            fingerprint TEXT UNIQUE NOT NULL,
            simhash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signature TEXT NOT NULL,
            license TEXT NOT NULL,
            file_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            registry_id INTEGER,
            certificate_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (registry_id) REFERENCES registry (id)
        )
    """)

    conn.commit()
    conn.close()


def get_db_connection():
    """Create database connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize DB when app starts
with app.app_context():
    init_database()


@app.route('/')
def index():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get all works
        cursor.execute('SELECT * FROM registry ORDER BY created_at DESC')
        works = cursor.fetchall()

        # Get statistics
        cursor.execute('SELECT COUNT(*) as total FROM registry')
        total_works = cursor.fetchone()['total']

        cursor.execute('SELECT work_type, COUNT(*) as count FROM registry GROUP BY work_type')
        type_stats = cursor.fetchall()

        conn.close()

        return render_template(
            'index.html',
            works=works,
            total_works=total_works,
            type_stats=type_stats
        )

    except Exception:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error — check deploy logs", 500


@app.route('/work/<int:work_id>')
def work_detail(work_id):
    """Detailed view of a single work"""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM registry WHERE id = ?',
        (work_id,)
    )

    work = cursor.fetchone()
    conn.close()

    if work:
        return render_template('work_detail.html', work=work)

    return "Work not found", 404


@app.route('/search')
def search():
    """Search functionality"""

    query = request.args.get('q', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM registry
        WHERE title LIKE ?
        OR creator LIKE ?
        OR work_type LIKE ?
        ORDER BY created_at DESC
    """, (
        f'%{query}%',
        f'%{query}%',
        f'%{query}%'
    ))

    works = cursor.fetchall()
    conn.close()

    return render_template(
        'search.html',
        works=works,
        query=query
    )


@app.route('/api/works')
def api_works():
    """API endpoint to get all works"""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM registry ORDER BY created_at DESC'
    )

    works = cursor.fetchall()
    conn.close()

    works_list = [dict(work) for work in works]

    return jsonify(works_list)


@app.route('/api/work/<int:work_id>')
def api_work(work_id):
    """API endpoint to get single work"""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM registry WHERE id = ?',
        (work_id,)
    )

    work = cursor.fetchone()
    conn.close()

    if work:
        return jsonify(dict(work))

    return jsonify({"error": "Work not found"}), 404


@app.route('/stats')
def stats():
    """Statistics page"""

    conn = get_db_connection()
    cursor = conn.cursor()

    # Overall stats
    cursor.execute('SELECT COUNT(*) as total FROM registry')
    total_works = cursor.fetchone()['total']

    cursor.execute("""
        SELECT work_type, COUNT(*) as count
        FROM registry
        GROUP BY work_type
    """)
    type_stats = cursor.fetchall()

    cursor.execute("""
        SELECT creator, COUNT(*) as count
        FROM registry
        GROUP BY creator
        ORDER BY count DESC
        LIMIT 10
    """)
    top_creators = cursor.fetchall()

    cursor.execute("""
        SELECT license, COUNT(*) as count
        FROM registry
        GROUP BY license
    """)
    license_stats = cursor.fetchall()

    conn.close()

    return render_template(
        'stats.html',
        total_works=total_works,
        type_stats=type_stats,
        top_creators=top_creators,
        license_stats=license_stats
    )


@app.route('/__health__')
def health():
    return {"status": "ok"}, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
