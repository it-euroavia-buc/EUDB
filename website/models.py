import pandas
from . import db
import pandas as pd
from flask import flash, session, redirect, url_for
from flask_login import UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.sql import func
from hashlib import md5

# CONSTANTS DEFINITION
ENCRYPTION_SALT = "EUROAVIA"


# FUNCTION THAT ADDS USERS TO THE DATABASE

class ModelFunctionality:

    def __init__(self) -> None:
        pass

    def transform_dbentry_to_df(self, db_entries: list, selectedtable) -> pd.DataFrame:

        full_data_for_df_list = []
        
        if selectedtable == 'user':
            selectedtable = 'users'

            db_entry_columns = ["last_name", "first_name", "CNP", "series", "number", "adress", 
                                "phonenumber", "college", "experience", "department"]
            df_columns = ["No. Crt.", "Last Name", "First Name", "CNP", "Series", "Series Number", "Address",
                            "Phone Number", "College", "Experience", "Department"]
            no_crt = 1

            for db_entry in db_entries:
                if db_entry.users is None:
                    continue

                current_data_for_df_list = [no_crt]
                no_crt += 1

                for db_entry_attribute in db_entry_columns:
                    current_data_for_df_list.append(getattr(getattr(db_entry, "users"), db_entry_attribute))

                full_data_for_df_list.append(current_data_for_df_list)

            return pd.DataFrame(data=full_data_for_df_list, columns=df_columns)

        db_extra_columns = ["role", "year"]
        df_columns = ["No. Crt.", "Last Name", "First Name", "Role", "Year"]
        no_crt = 1

        for db_entry in db_entries:
            if db_entry.users is None:
                    continue
            
            current_data = [no_crt, db_entry.users.last_name, db_entry.users.first_name]
            for extra_col in db_extra_columns:
                specific_table_entry = getattr(db_entry.users, selectedtable)

                if specific_table_entry is None:
                    break

                current_data.append(getattr(specific_table_entry, extra_col))

            else:
                full_data_for_df_list.append(current_data)
                no_crt += 1

        return pd.DataFrame(data=full_data_for_df_list, columns=df_columns)


    def encrypt_password(self, given_password: str) -> str:
        """
        Function which encrypts the given password using md5 encryption.

        :param given_password: Password to be encrypted
        :type given_password: str
        :return: Encrypted password
        :return type: str
        """
        password_to_encode = given_password + ENCRYPTION_SALT
        encrypted_password = md5(password_to_encode.encode()).hexdigest()

        return encrypted_password


    def check_user_login(self, email, password):
        user = Credentials.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist',category='error')
            return -1
        
        encrypted_user_password = self.encrypt_password(password)
        if user.password != encrypted_user_password:
            flash('Incorrect password', category='error')
            return -1

        login_user(user, remember=True)

        encrypted_generated_password = self.encrypt_password(user.generated_password)

        if user.password == encrypted_generated_password:
            flash('passwords match',category= 'succes')
            return False

        return True
    
    def change_user_password(self, email, password1, password2):
        user = Credentials.query.filter_by(email=email).first()

        if email != current_user.email:
            flash('Incorrect email', category='error')
            return -1
    
        if len(password1) < 7:
            flash("Password must be at least 8 characters ", category='error')
            return -1
        
        if password1 != password2:
            flash("Passwords don't match", category='error')
            return -1
        
        user.password =  self.encrypt_password(password1)
        db.session.commit()
        flash("Password changed", category= 'succes')
        login_user(user, remember=True)
        return True


    def parse_data(self, data):

        i = 0
        k = 0
        messages = {
            'errors': [],
            'success': []
        }
        for idx, row in data.iterrows():

            i += 1

            firstName = str(row["Prenume"])
            lastName = str(row["Nume"])
            email = str(row["Email"])
            CNP = row["CNP"]
            series = row["Serie Buletin"]
            number = row["Nr buletin"]
            address = row["Adresa domiciliu"]
            phonenumber = row["Telefon"]
            college = row["Facultate"]
            experience = row["Experienta in EA (ani)"]
            department = row["Departament"]
            subdepartment = row["Subdepartament"]
            mentiuni = row["Mentiuni"]
            year=row["Year"]
            level = "USER"
            generated_password = "TEST12345"

            event_columns = ["AcWo", "ACC", "AeroCamp", "DroWo", "Freshers", "HSS", "RoWo", "WiCa"]
            user_columns = []
            roles=[]
            for ev_column in event_columns:
                role = row[ev_column]
                if type(role)==str:
                    user_columns.append(ev_column)
                    roles.append(role)
            user_event_dict={
                "AcWo":AcWo,
                "ACC":ACC,
                "AeroCamp":AeroCamp,
                "DroWo":DroWo,
                "Freshers":Freshers,
                "HSS":HSS,
                "RoWo":RoWo,
                "WiCa":WiCa

            }

            user_event_list=[user_event_dict[event] for event in user_columns]


            credential_id = self.add_credentials(email=email,
                                                 generated_password=generated_password,
                                                 level=level
                                                 )
            if credential_id == -1:
                message = 'Failed to add user at position ' + str(i + 1) + ' in file'
                messages['errors'].append(message)
                k += 1
                continue
            user_id = self.add_user(credential_id=credential_id,
                                    last_name=lastName,
                                    first_name=firstName,
                                    CNP=CNP,
                                    series=series,
                                    number=number,
                                    adress=address,
                                    phonenumber=phonenumber,
                                    college=college,
                                    experience=experience,
                                    department=department,
                                    subdepartment=subdepartment,
                                    mention=mentiuni
                                    )
            if user_event_list:
                self.add_user_event(events=user_event_list, user_id=user_id, roles=roles, year=year)
        message = 'Added ' + str(i - k) + ' Users to Database'
        messages['success'].append(message)
        session['flashes'] = messages.copy()
        i = 0
        k = 0

    def add_credentials(self, email, generated_password, level):

        credential = Credentials.query.filter_by(email=email).first()

        if credential:
            print('user exists')
            return -1

        if len(email) < 4:
            print('email')
            return -1

        if len(generated_password) < 7:
            print('password')
            return -1

        if level not in ['USER', 'ADMIN', 'SUPER ADMIN']:
            print('invalid power level')
            return -1

        try:

            new_credential = Credentials(email=email,
                                         password=self.encrypt_password(generated_password),
                                         generated_password=generated_password, level=level)
            db.session.add(new_credential)
            db.session.commit()
            return new_credential.id
        except Exception as e:
            flash(f"there was an error trying to add an user: {e}", category='error')
            return -1

    def add_user(self, credential_id, last_name, first_name, CNP, series, number, adress, phonenumber, college,
                 experience, department, subdepartment, mention):

        user = User.query.filter_by(credential_id=credential_id).first()

        if user:
            print('user exists')
            return -1
            # flash('A user with this email already exists', category='error')
        try:
            new_user = User(credential_id=credential_id,
                            last_name=last_name,
                            first_name=first_name,
                            CNP=CNP,
                            series=series,
                            number=number,
                            adress=adress,
                            phonenumber=phonenumber,
                            college=college,
                            experience=experience,
                            department=department,
                            subdepartment=subdepartment,
                            mention=mention)

            db.session.add(new_user)
            db.session.commit()
            return new_user.id
        except Exception as e:
            flash(f"there was an error trying to add an user to the Usertable: {e}", category='error')
            return -1
        # flash('User Added', category='success')

    def add_user_event(self, events, user_id, roles, year):

        for idx, event in enumerate(events):
            try:
                new_user_event=event(user_id=user_id, role=roles[idx], year=year)
                db.session.add(new_user_event)
                db.session.commit()
            except Exception as e:
                flash(f"there was an error trying to add an user to {event}: {e}", category='error')

    def edit_user(self,credential_id, email, last_name, first_name, CNP, series, number, adress, phonenumber, college, experience, department, subdepartment, mention):

        credential = Credentials.query.filter_by(id=credential_id).first()

        if credential:

            if len(email) < 4:
                flash('email must be greater than 4 characters', category='error')
                return -1

            credential.email=email
            credential.users.last_name=last_name
            credential.users.first_name=first_name
            credential.users.CNP=CNP
            credential.users.series=series
            credential.users.number=number
            credential.users.adress=adress
            credential.users.phonenumber=phonenumber
            credential.users.college=college
            credential.users.experience=experience
            credential.users.department=department
            credential.users.subdepartment=subdepartment
            credential.users.mention=mention

            flash('modified data successfully!', category='success')

            print('editing user')
            db.session.commit()
            return 0
        flash('error', category='error')
        return -1

    def delete_table(self, table_name):

        tables_dict={
                "acwo":AcWo,
                "acc":ACC,
                "aerocamp":AeroCamp,
                "credentials": Credentials,
                "drowo":DroWo,
                "freshers":Freshers,
                "hss":HSS,
                "rowo":RoWo,
                "user": User,
                "wica":WiCa
            }

        try:
            if table_name == 'user' or table_name == 'credentials':
                for t_d in tables_dict.keys():
                    if t_d == 'credentials':
                        Credentials.query.filter_by(level = "USER").delete()
                    else:
                        tables_dict[t_d].query.delete()
                db.session.commit()
            else:
                table = tables_dict[table_name]
                table.query.delete()
                db.session.commit()
        except Exception as e:
            flash("there is no such table")

    def change_password(self, user_id, new_password):
        
        user = Credentials.query.filter_by(id = user_id).first()
        user.generated_password = new_password
        user.password = self.encrypt_password(new_password)
        db.session.commit()

        
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(1000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Credentials(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    generated_password = db.Column(db.String(150))
    users = db.relationship('User', uselist=False, backref='credentials')
    # users = db.relationship('User', back_populates='child_user', uselist=False, backref='credentials')

    def __init__(self,
                 level=None,
                 email=None,
                 password=None,
                 generated_password=None,
                 ):
        self.level = level
        self.email = email
        self.password = password
        self.generated_password = generated_password


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'))
    # child_user = db.relationship('Credentials', back_populates='users')
    last_name = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    CNP = db.Column(db.String(10))
    series = db.Column(db.String(150))
    number = db.Column(db.Integer())
    adress = db.Column(db.String(150))
    phonenumber = db.Column(db.String(150))
    college = db.Column(db.String(150))
    experience = db.Column(db.String(150))
    department = db.Column(db.String(150))
    subdepartment = db.Column(db.String(150))
    mention = db.Column(db.String(150))
    notes = db.relationship('Note')
    freshers = db.relationship('Freshers', uselist=False, back_populates = "child_freshers")
    acwo = db.relationship('AcWo', uselist=False, back_populates = "child_acwo")
    hss = db.relationship('HSS', back_populates="child_hss", uselist=False)
    aerocamp = db.relationship('AeroCamp', back_populates="child_aerocamp", uselist=False)
    rowo = db.relationship('RoWo', back_populates="child_rowo", uselist=False)
    drowo = db.relationship('DroWo', back_populates="child_drowo", uselist=False)
    acc = db.relationship('ACC', back_populates="child_acc", uselist=False)
    wica = db.relationship('WiCa', back_populates="child_wica", uselist=False)

    def __init__(self,
                 credential_id=None,
                 last_name=None,
                 first_name=None,
                 CNP=None,
                 series=None,
                 number=None,
                 adress=None,
                 phonenumber=None,
                 college=None,
                 experience=None,
                 department=None,
                 subdepartment=None,
                 mention=None
                 ):
        self.credential_id = credential_id
        self.last_name = last_name
        self.first_name = first_name
        self.CNP = CNP
        self.series = series
        self.number = number
        self.adress = adress
        self.phonenumber = phonenumber
        self.college = college
        self.experience = experience
        self.department = department
        self.subdepartment = subdepartment
        self.mention = mention


class Freshers(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_freshers = db.relationship('User', back_populates="freshers")


class AcWo(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_acwo = db.relationship('User', back_populates="acwo")


class HSS(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_hss = db.relationship('User', back_populates="hss")


class AeroCamp(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_aerocamp = db.relationship('User', back_populates="aerocamp")


class RoWo(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_rowo = db.relationship('User', back_populates="rowo")


class DroWo(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_drowo = db.relationship('User', back_populates="drowo")


class ACC(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_acc = db.relationship('User', back_populates="acc")


class WiCa(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(150))
    year = db.Column(db.Integer)
    child_wica = db.relationship('User', back_populates="wica")


