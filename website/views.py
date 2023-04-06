#TK-021 DATABASE ENTRY BACKEND

from flask import Blueprint, render_template, request, flash, jsonify,current_app,redirect, url_for,send_from_directory,session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .models import Note, User, Credentials, ModelFunctionality
from . import db
import pandas as pd
import json
import os
import sqlalchemy as sql_al
from sqlalchemy import desc,asc

views = Blueprint('views', __name__)
data = []

def print_flashes():
    print('intrat in functie')
    if "flashes" in session:
        if session['flashes']:
            print('intrat in if')
            print(session['flashes'])
            errorflashes = session['flashes']['errors']
            successflashes = session['flashes']['success']

            for errorflash in errorflashes:
                flash(errorflash,category='error')
            for successflash in successflashes:
                flash(successflash,category='success')


def clear_flashes():
    if "flashes" in session:
        session['flashes']={
            'errors':[],
            'success':[]
        }

#FUNCTION THAT STORES FILE WHILE THEY ARE PROCESSED, VERIFIES FILE EXTENSION AS WELL AS SECURE FILENAMES
def process_file(file):
    if file:
                    
        filename = secure_filename(file.filename)
        extension = filename.rsplit('.', 1)[1].lower()

        file.save(os.path.join(current_app.instance_path, 'uploads', filename))
        filepath = current_app.instance_path + '/uploads/' + filename

        print(extension)
        if extension == 'csv':

            data = pd.read_csv(filepath)

            ModelFunctionality().parse_data(data)

        elif extension == 'xlsx':

            data = pd.read_excel(filepath)

            ModelFunctionality().parse_data(data)

        else:
            message='File extension is not allowed, please use .csv or .xlsx'
            session['flashes']['errors'].append(message)
            print("ADDED MESSAGE TO SESSION ##################################")
            

        os.remove(os.path.join(current_app.instance_path, 'uploads', filename))
    else:
        flash('No file part', category = 'error')
        
#FUNCTION THAT SPLITS FILES (WORKS FOR BOTH SINGLE FILE METHOD AS WELL AS DRAG AND DROP METHOD)
def process_files(files):
    clear_flashes()
    for upfile in files:
        file = files.get(upfile)
        print('we have a file!',file.filename)
        flash('Processing File', category = 'success')
        process_file(file)

@views.route('/database-entry',methods=['GET','POST'])
@login_required
def dbentry():
    if request.method == 'POST':

        files = request.files
        process_files(files)
        print_flashes()

        return redirect(url_for('views.dbentry'))
    
    return render_template("dbentry.html", user=current_user)

@views.route('/table_manager',methods=['GET','POST'])
@login_required
def table_manager():

    users = Credentials.query.all()
    
    data_table = None
    tables=[]
    selectedtable = 'user'

    try:
        data_table = ModelFunctionality().transform_dbentry_to_df(users, selectedtable)
    except Exception as e:
        flash(f"Something went wrong trying to display the table: {e}.", category="error")

    for t in db.metadata.tables:
        tables.append(t)

    tables.remove('credentials')

    if request.method == 'POST':

        selectedtable = request.form.get('selecttable')

        try:
            data_table = ModelFunctionality().transform_dbentry_to_df(users, selectedtable)
        except Exception as e:
            flash(f"Something went wrong trying to display the table: {e}.", category="error")
    
    return render_template("table_manager.html",selectedtable=selectedtable, tables=tables, users=users, user=current_user, data_table=data_table)

@views.route('/download-xlsx', methods=['GET'])
def downloadxlsx():
    dir = os.path.join(current_app.instance_path)
    filename = 'excel_template.xlsx'
    return send_from_directory(dir,filename)

@views.route('/download-csv', methods=['GET'])
def downloadcsv():
    dir = os.path.join(current_app.instance_path)
    filename = 'csv_template.csv'
    return send_from_directory(dir,filename)

#MEMBER PRIVATE PAGE
@views.route('/member-page', methods=['GET'])
@login_required
def memberpage():
    return render_template("memberpage.html", user=current_user)

@views.route('/edit-member-page',methods=['GET','POST'])
@login_required
def editmemberpage():
    if request.method == 'POST':

        lastName = request.form.get('last_name')
        firstName = request.form.get('first_name')
        cnp = request.form.get('CNP')
        series = request.form.get('series')
        number = request.form.get('number')
        adress = request.form.get('adress')
        college = request.form.get('college')
        email = request.form.get('email')
        phonenumber = request.form.get('phonenumber')
        credential_id = current_user.id
        experience = current_user.users.experience
        department = current_user.users.department
        subdepartment = current_user.users.subdepartment
        mention = current_user.users.mention

        if ModelFunctionality().edit_user(credential_id, email, lastName, firstName, cnp, series, number, adress, phonenumber, college, experience, department, subdepartment, mention) == 0:
            return redirect(url_for('views.memberpage'))
        else:
            flash('Failed to modify data!', category='error')
            return redirect(url_for('views.editmemberpage'))
    return render_template("editmemberpage.html", user=current_user)

#TESTING VIEWS (NO USE FOR TK-021)

@views.route('/testdata', methods=['GET'])
@login_required
def testdata():
    global data
    return render_template("testdata.html", user=current_user, data=data)

@views.route('/', methods=['GET', 'POST'])   
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')
        if len(note) < 1:
            flash('Note length must be greater than 1 character', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')
    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify()

#SUPER ADMIN

@views.route('/super_admin', methods = ['GET', 'POST'])
@login_required
def super_admin():

    # if current_user.level != "SUPER ADMIN":
    #     return redirect(url_for('views.home'))

    admins = Credentials.query.filter_by(level = "ADMIN").all()
    super_admins = Credentials.query.filter_by(level = "SUPER ADMIN").all()
    for sa in super_admins:
        admins.append(sa)
    
    if request.method == 'POST':
        if request.form.get('add_admin') == 'add_admin':
            return redirect(url_for('views.add_admin'))
        elif request.form.get('download') == 'download':
            pass
        elif request.form.get('delete') == 'delete' :
            id = request.form.get('delete_value')
            del_user = Credentials.query.filter_by(id=id).first()
            db.session.delete(del_user)
            db.session.commit()
            return redirect(url_for('views.super_admin'))
        elif request.form.get('change') == 'change':
            id = request.form.get('change_value')
            print(id)
            user = Credentials.query.filter_by(id = id).first()
            session['change_password'] = user.id
            print(session['change_password'])
            return redirect(url_for('views.change_password'))
        elif request.form.get('delete_table') == 'delete_table':
            return redirect(url_for('views.delete_table'))

    return render_template('super_admin.html', admins  = admins, user=current_user)

@views.route('/add_admin', methods = ['GET', 'POST'])
@login_required
def add_admin():
    
    if request.method == "POST":
        level = request.form.get('level')
        email = request.form.get('email')
        password = request.form.get('password')

        modelfunc = ModelFunctionality()
        modelfunc.add_credentials(level=level, generated_password=password, email=email)

    return render_template('add_admin.html', user= current_user)

@views.route('/delete_table', methods = ['GET', 'POST'])
@login_required
def delete_table():

    if request.method == "POST":
        table_name = request.form.get('tabels')

        modelfunc = ModelFunctionality()
        modelfunc.delete_table(table_name)


    return render_template('delete_table.html', user = current_user)

@views.route('/change_password', methods = ['GET', 'POST'])
@login_required
def change_password():

    user = Credentials.query.filter_by(id = session['change_password']).first()
    if not user:
        return redirect(url_for('views.home'))
    
    if request.method == "POST":
        new_password = request.form.get('new_password')
        print('new_password')
        modelfunc = ModelFunctionality()
        modelfunc.change_password(user.id, new_password)


    return render_template('change_password_admin.html', user = current_user)
