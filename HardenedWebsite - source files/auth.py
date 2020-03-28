import functools
import bcrypt

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db
from config import pepper

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
            "SELECT username FROM users WHERE username LIKE ?", (username,)
        ).fetchone()

        if user is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            salt = bcrypt.gensalt()
            p = password.encode('utf-8') + pepper.encode('utf-8')
            hashed = bcrypt.hashpw(p, salt)
            finalpw = hashed.decode('utf8')
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, finalpw)
            )
            db.execute(
                'INSERT INTO accounts (username, balance) VALUES (?, ?)',
                (username, '0')
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    db = get_db()
    admin = db.execute(
        'SELECT id FROM users WHERE id = 1'
    ).fetchone()

    if admin is None:
        password = 'gotTheMoney'
        salt = bcrypt.gensalt()
        p = password.encode('utf-8') + pepper.encode('utf-8')
        hashed = bcrypt.hashpw(p, salt)
        finalpw = hashed.decode('utf8')

        db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
            ('admin', finalpw)
        )
        db.execute('INSERT INTO accounts (username, balance) VALUES (?, ?)',
            ('admin', '5000')
        )
        db.commit()  

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        p = password.encode('utf-8') + pepper.encode('utf-8')
        user = db.execute(
            "SELECT username FROM users WHERE username LIKE ?", (username,)
        ).fetchone()
        pw = db.execute(
            "SELECT password FROM users WHERE username LIKE ?", (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'

        elif not (bcrypt.checkpw(p, pw[0].encode('utf-8'))):
            error = 'Incorrect password.'

        if error is None:
            print("user: " + user['username'] + " and password: " + pw['password']);
            userid = db.execute(
                "SELECT id FROM users WHERE username LIKE ?", (username,)
            ).fetchone()

            session.clear()
            session['user_id'] = userid['id'];
            
            # session['user_id'] = user['id']
            return redirect(url_for('blog.index'))
       
        flash(error)
        return redirect(url_for('auth.login'))
        
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    db = get_db()
    
    if user_id is None:
        g.user = None
    else:
        userid = str(user_id)
        g.user  = db.execute(
            "SELECT * FROM users WHERE id LIKE ?", (userid,)
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