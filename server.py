import csv
import io
import os
import secrets
import sqlite3
from functools import wraps
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
DB_PATH = os.environ.get('DB_PATH', 'dashboard.db')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change-this-now')


def connect():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con


def init_db():
    with connect() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL UNIQUE,
            nickname TEXT NOT NULL DEFAULT '',
            region TEXT NOT NULL DEFAULT '',
            level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 999),
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')

init_db()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response


@app.get('/login')
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('login.html')


@app.post('/login')
def login_post():
    supplied = request.form.get('password', '')
    # Hash the configured password on demand; never store it in the database.
    expected_hash = generate_password_hash(ADMIN_PASSWORD)
    if ADMIN_PASSWORD != 'change-this-now' and check_password_hash(expected_hash, supplied):
        session.clear()
        session['logged_in'] = True
        session.permanent = True
        return redirect(url_for('index'))
    flash('পাসওয়ার্ড ভুল, অথবা Render-এ ADMIN_PASSWORD সেট করা হয়নি।', 'error')
    return redirect(url_for('login'))


@app.get('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.get('/')
@login_required
def index():
    q = request.args.get('q', '').strip()
    with connect() as con:
        if q:
            rows = con.execute('''SELECT * FROM accounts WHERE uid LIKE ? OR nickname LIKE ? OR region LIKE ? ORDER BY id DESC''', (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
        else:
            rows = con.execute('SELECT * FROM accounts ORDER BY id DESC').fetchall()
        total = con.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]
    return render_template('index.html', rows=rows, total=total, q=q)


def validated_form():
    uid = request.form.get('uid', '').strip()
    nickname = request.form.get('nickname', '').strip()[:80]
    region = request.form.get('region', '').strip()[:40]
    notes = request.form.get('notes', '').strip()[:500]
    try:
        level = int(request.form.get('level', ''))
    except ValueError:
        raise ValueError('Level অবশ্যই সংখ্যা হতে হবে।')
    if not uid or len(uid) > 40:
        raise ValueError('UID ১ থেকে ৪০ অক্ষরের মধ্যে দিন।')
    if not 1 <= level <= 999:
        raise ValueError('Level ১ থেকে ৯৯৯-এর মধ্যে দিন।')
    return uid, nickname, region, level, notes


@app.post('/add')
@login_required
def add():
    try:
        values = validated_form()
        with connect() as con:
            con.execute('INSERT INTO accounts(uid,nickname,region,level,notes) VALUES(?,?,?,?,?)', values)
        flash('অ্যাকাউন্ট যোগ হয়েছে।', 'success')
    except sqlite3.IntegrityError:
        flash('এই UID আগে থেকেই তালিকায় আছে।', 'error')
    except ValueError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('index'))


@app.post('/edit/<int:account_id>')
@login_required
def edit(account_id):
    try:
        uid, nickname, region, level, notes = validated_form()
        with connect() as con:
            cur = con.execute('''UPDATE accounts SET uid=?,nickname=?,region=?,level=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?''', (uid,nickname,region,level,notes,account_id))
        flash('অ্যাকাউন্ট আপডেট হয়েছে।' if cur.rowcount else 'অ্যাকাউন্ট পাওয়া যায়নি।', 'success' if cur.rowcount else 'error')
    except sqlite3.IntegrityError:
        flash('এই UID অন্য একটি এন্ট্রিতে আছে।', 'error')
    except ValueError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('index'))


@app.post('/delete/<int:account_id>')
@login_required
def delete(account_id):
    with connect() as con:
        con.execute('DELETE FROM accounts WHERE id=?', (account_id,))
    flash('অ্যাকাউন্ট মুছে ফেলা হয়েছে।', 'success')
    return redirect(url_for('index'))


@app.get('/export.csv')
@login_required
def export_csv():
    with connect() as con:
        rows = con.execute('SELECT uid,nickname,region,level,notes,created_at,updated_at FROM accounts ORDER BY id').fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['UID','Name','Region','Level','Notes','Created','Updated'])
    writer.writerows([tuple(row) for row in rows])
    return Response('\ufeff' + output.getvalue(), mimetype='text/csv; charset=utf-8', headers={'Content-Disposition':'attachment; filename=accounts.csv'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
