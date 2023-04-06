"""
1. Fisierul __init__.py al programului - aici se creaza efectiv web app-ul si baza de date
2. De modificat: 
    - trebuie sa agaugam partea de flask_login (pentru partea de admin)-> folositi Documentatia Flask
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"
DB_PATH = os.path.join("../instance", DB_NAME)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'un_cod_irelevant_la_nivelul_la_care_lucram'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'

    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note, Credentials


    dirpath = app.instance_path + '/uploads'
    create_database(app)
    create_uploads(app, dirpath)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return Credentials.query.get(int(id))

    return app

def create_uploads(app, dirpath):
    if not path.exists(dirpath):
        os.mkdir(dirpath)
    print('Created Upload Directory')

def create_database(app):
    if not path.exists(DB_PATH):
        with app.app_context():
            db.create_all()
        print('Created Database')
