from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from auth import login_required
from db import get_db
from auth import session
from wtforms import Form, StringField, SelectField
from forms import DateSearchForm
from datetime import date

bp = Blueprint('blog', __name__)

@bp.route('/create', methods=('GET', 'POST'))
def create():
    secret = 'dev'
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':

        key = request.form['token']
        if key == 'dev':
            results = []
            total = request.form['amount']
            account = request.form['account']
            user_id = request.args.get('user_id')
            name = g.user[1]
            print(name)
            error = None

            if total is None:
                error = 'Transfer amount is required.'
            if account is None:
                error = 'Account username is required'
            if total is '0':
                error = 'Amount cannot be zero'
            if error is not None:
                flash(error)
            else:
                current_balance_user = db.execute(
                    "SELECT balance FROM accounts WHERE username = ?", (name, )
                ).fetchone()
                
                current_balance_target = db.execute(
                    "SELECT balance FROM accounts WHERE username = ?", (account, )
                ).fetchone()

                if current_balance_target is not None:
                    if int(total) <= int(current_balance_user[0]):

                        new_balance_user = int(current_balance_user[0]) - int(total)
                        new_balance_target = int(current_balance_target[0]) + int(total)
                        db.execute("UPDATE accounts SET balance = ? WHERE username = ?", (new_balance_target, account))
                        db.execute("UPDATE accounts SET balance = ? WHERE username = ?", (new_balance_user, name))
                        db.commit();

                        results = db.execute(
                            "SELECT * FROM accounts WHERE username = ? OR username = ?", (name, account)
                        ).fetchall()

                        db.execute(
                            "INSERT INTO transactions (username, date, amount) VALUES (?, ?, ?)", 
                            (name, date.today(), total)
                        )
                        db.commit();

                        return render_template('blog/create.html', results=results)

    guser = g.user[1]
    balance = db.execute(
        "SELECT * FROM accounts WHERE username LIKE ?", (guser, )
    ).fetchone()
    session['balance'] = balance[2]

    user_id = request.args.get('user_id')
    return render_template('blog/create.html')

@bp.route('/update', methods=('GET', 'POST'))
def update():
    search = DateSearchForm(request.form)
    if request.method == 'POST':
        return search_results(search)
    user_id = request.args.get('user_id')
    return render_template('blog/update.html', form=search)

def search_results(search):
    results = []
    user_id = g.user[0]
    search_string = search.data['search']
    db = get_db()
    name = g.user[1]
    print(name)
    results = db.execute(
        "SELECT * FROM transactions WHERE date = ? AND username = ?", (search_string, name)
    ).fetchall()

    return render_template('blog/update.html', form=search, results=results)


@bp.route('/index', methods=('GET', 'POST'))
def index():
    if request.method == 'POST':
        secretWord = request.form['secretWord']
        user_id = g.user[0]
        db = get_db()
        error = None

        if not secretWord:
            error = 'Secret Word is required.'

        if error is not None:
            flash(error)

        if error is None:
            db.execute(
                "UPDATE users SET secretKey = ? WHERE username LIKE ?",
                (secretWord, g.user[1])
            )

            db.commit()
            return redirect(url_for('blog.index'))

    elif request.method == 'GET':
        db = get_db()
        user_id = session.get('user_id')
        
        secretKey = db.execute(
            "SELECT secretKey FROM users WHERE CAST(id as CHAR) LIKE ?", (str(user_id).encode('utf-8'), )
        ).fetchone()
        session['secretWord'] = secretKey

        return render_template('blog/index.html')
