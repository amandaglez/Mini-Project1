import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, make_response
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        
        user = db.execute(
            "SELECT username FROM users WHERE username LIKE ?", (username, )
        ).fetchone()

        if user is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, password)
            )
            db.execute(
                'INSERT INTO accounts (username, balance) VALUES (?, ?)',
                (username, '0')
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        user = db.execute(
            "SELECT username FROM users WHERE username LIKE ?", [username]
        ).fetchone()
        pw = db.execute(
            "SELECT password FROM users WHERE username LIKE ?", [username]
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        # elif not check_password_hash(user['password'], password):
            # error = 'Incorrect password.'

        elif not (pw['password'] == password):
            error = 'Incorrect password.'

        if error is None:
            print("user: " + user['username'] + " and password: " + pw['password']);
            
            userid = db.execute(
                "SELECT id FROM users WHERE username LIKE ?", [username]
            ).fetchone()
            user_id = str(userid[0])

            g.user = db.execute(
                "SELECT * FROM users WHERE username LIKE ?", [username]
            ).fetchone()

            return redirect(url_for('blog.index', user_id=user_id))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = request.args.get('user_id')
    db = get_db()
    cursor = db.cursor()

    if user_id is None:
        g.user = None
    else:        
        g.user = db.execute(
            "SELECT * FROM users WHERE CAST(id as CHAR) LIKE ?", (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
