from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Connexion réussie !", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash(f"Mauvais mot de passe !", category='error')
        else:
            flash('Email incorrect !', category='error')


    data = request.form
    print(data)
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.home'))
    flash('Déconnexion réussie !', category='success')

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email = email).first()

        if user:
            flash('Email deja utilisé !', category='error')
        if len(email) < 4:
            flash('Email incorrect', category='error')
        elif len(firstname) < 2:
            flash('Le prénom doit faire au moins 2 caractères', category='error')
        elif len(lastname) < 2:
            flash('Le nom de famille doit faire au moins 2 caractères', category='error')
        elif password1 != password2:
            flash('Les mots de passe ne correspondent pas', category='error')
        elif len(password1) < 8:
            flash('Le mot de passe doit faire au moins 8 caractères', category='error')
        else:
            new_user = User(username=username, email=email, firstname=firstname, lastname=lastname, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Compte créé !', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
