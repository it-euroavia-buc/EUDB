from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Credentials, ModelFunctionality 
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/change_password', methods = ['GET', 'POST'])
@login_required
def change_password():
    if request.method== 'POST':
        email = request.form.get('email')
        
        password1 = request.form.get('password1') #parola noua
        password2 = request.form.get('password2') #parola nou confirmata
        redirect_home = ModelFunctionality().change_user_password(email=email, password1=password1, password2=password2)
        if type(redirect_home) == bool and redirect_home:
            return redirect(url_for("views.home"))
       
    return render_template("change_password.html", user=current_user)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        redirect_home = ModelFunctionality().check_user_login(email=email, password=password)

        if type(redirect_home) != bool:
            return render_template("login.html", user=current_user)
    
        if redirect_home:
            return redirect(url_for("views.home"))
        
        # in case the passwords needs to be changed
        elif not redirect_home:
            return redirect(url_for("auth.change_password"))
        
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
