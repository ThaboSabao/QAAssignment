from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, NumberRange
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
import re

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'lNNmwChzSC'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'Login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Integer, nullable=False, default=1)
    company_id = db.Column(
        db.Integer, db.ForeignKey('company.id'), nullable=True)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    users = db.relationship('User', backref='company', lazy=True)
    yards = db.relationship('Yard', backref='company', lazy=True)


class Yard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    company_id = db.Column(
        db.Integer, db.ForeignKey('company.id'), nullable=True)
    vehicles = db.relationship('Vehicle', backref='yard', lazy=False)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vin = db.Column(db.String(17), nullable=False)
    make = db.Column(db.String(30), nullable=True)
    model = db.Column(db.String(30), nullable=True)
    variant = db.Column(db.String(30), nullable=True)
    colour = db.Column(db.String(30), nullable=True)
    status = db.Column(db.Integer, nullable=False, default=0)
    yard_id = db.Column(db.Integer, db.ForeignKey('yard.id'), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), Length(
        min=6, max=40)], render_kw={'placeholder': 'Password'})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                'Username already exists'
            )


class CompanyRegistrationForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        max=50)], render_kw={'placeholder': 'Company name'})
    submit = SubmitField('Create company')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), Length(
        min=6, max=40)], render_kw={'placeholder': 'Password'})
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': 'Username'})
    role = SelectField(u'Role')
    company_id = SelectField(u'Company')
    submit = SubmitField('Confirm edit')

class VehicleForm(FlaskForm):
    vin = StringField(validators=[InputRequired(), Length(
        min=7, max=17)], render_kw={'placeholder': 'Vin'})
    make = StringField(validators=[Length(max=20)], render_kw={
                       'placeholder': 'Make'})
    model = StringField(validators=[Length(max=20)], render_kw={
                        'placeholder': 'Model'})
    variant = StringField(validators=[Length(max=30)], render_kw={
                          'placeholder': 'Variant'})
    colour = StringField(validators=[Length(max=20)], render_kw={
                         'placeholder': 'Colour'})
    yard_id = SelectField(u'Yard')
    submit = SubmitField('Create vehicle')


class YardForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={'placeholder': 'Name'})
    address = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={'placeholder': 'Address'})
    capacity = IntegerField(validators=[InputRequired(), NumberRange(
        min=0)], render_kw={'placeholder': 'Capacity'})
    submit = SubmitField('Create yard')


@app.route('/')
def Home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def Register():
    form = RegistrationForm()

    if form.validate_on_submit() and re.fullmatch(r'[A-Za-z0-9@#$%^&+=]{8,}', form.password.data):
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session.pop('_flashes', None)
        return redirect(url_for('Login'))
    else:
        flash('Please enter a valid password.', 'warning')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def Login():
    form = LoginForm()

    if form.validate_on_submit() and re.fullmatch(r'[A-Za-z0-9@#$%^&+=]{8,}', form.password.data):
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['was_logged_in'] = True
                session.pop('_flashes', None)
                return redirect(url_for('Dashboard'))
    else:
        flash('Please enter valid login information')
    return render_template('login.html', form=form)


@app.route('/logout')
def LogOut():
    logout_user()
    if session.get('was_logged_in'):
        del session['was_logged_in']
    flash(f'You have been logged out', 'info')
    return redirect(url_for('Home'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def Dashboard():
    company = {}
    yards = {}
    if current_user.company_id:
        company = Company.query.filter_by(id=current_user.company_id).first()
        yards = Yard.query.filter_by(company_id=current_user.company_id).all()
        session.pop('_flashes', None)

    return render_template('dashboard.html', company=company, yards=yards)


@app.route('/company', methods=['GET', 'POST'])
@login_required
def CompanyPage():
    form = CompanyRegistrationForm()
    if form.validate_on_submit():
        new_company = Company(name=form.name.data)
        db.session.add(new_company)
        db.session.flush()
        user = User.query.filter_by(id=current_user.id).first()
        user.company_id = new_company.id
        db.session.commit()
        return redirect(url_for('Dashboard'))

    return render_template('company.html', form=form)

@app.route('/vehicle/<int:id>', methods=['GET'])
@login_required
def ViewVehicle(id):
    vehicle = Vehicle.query.filter_by(id=id).first()
    return render_template('vehicle.html', vehicle=vehicle)

@app.route('/vehicle/create', methods=['GET', 'POST'])
@login_required
def CreateVehicle():
    form = VehicleForm()
    yards = Yard.query.filter_by(company_id=current_user.company_id).all()
    form.yard_id.choices = [(y.id, y.name) for y in yards]

    if form.validate_on_submit():
        new_vehicle = Vehicle(vin=form.vin.data, make=form.make.data, model=form.model.data,
                              variant=form.variant.data, colour=form.colour.data, yard_id=form.yard_id.data)
        db.session.add(new_vehicle)
        db.session.commit()
        return redirect(url_for('Dashboard'))

    return render_template('vehicle_create.html', form=form)

def find_yards(yards, yard_id):
    for yard in yards:
        if yard.id == yard_id:
            return yard

@app.route('/vehicle/delete/<int:id>')
@login_required
def DeleteVehicle(id):
    user = User.query.filter_by(id=current_user.id).first()
    yards = Yard.query.filter_by(company_id=user.company_id).all()

    
    vehicle_to_delete = Vehicle.query.filter_by(id=id).first()

    y = find_yards(yards, user.company_id)
    if y is None:
        return

    db.session.delete(vehicle_to_delete)
    db.session.commit()
    flash(f'Vehicle deleted')
    company = {}
    yards = {}
    if current_user.company_id:
        company = Company.query.filter_by(id=current_user.company_id).first()
        yards = Yard.query.filter_by(company_id=current_user.company_id).all()

    return redirect(url_for('Dashboard', company=company, yards=yards))

@app.route('/vehicle/delete/confirm/<int:id>')
@login_required
def ConfirmVehicleDelete(id):
    vehicle = Vehicle.query.filter_by(id=id).first()

    return render_template('confirm_vehicle_delete.html', vehicle=vehicle)

@app.route('/vehicle/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def EditVehicle(id):
    vehicle_to_edit = Vehicle.query.filter_by(id=id).first()
    form = VehicleForm(obj=vehicle_to_edit)
    yards = Yard.query.filter_by(company_id=current_user.company_id).all()
    form.yard_id.choices = [(y.id, y.name) for y in yards]

    if request.method == 'POST' and form.validate_on_submit():
        vehicle_to_edit.vin = form.data['vin']
        vehicle_to_edit.make = form.data['make']
        vehicle_to_edit.model = form.data['model']
        vehicle_to_edit.variant = form.data['variant']
        vehicle_to_edit.colour = form.data['colour']
        vehicle_to_edit.yard_id = form.data['yard_id']
        db.session.commit()
        return redirect(url_for('Dashboard'))
    return render_template('vehicle_edit.html', form=form)

@app.route('/yard', methods=['GET', 'POST'])
@login_required
def CreateYard():
    form = YardForm()

    if form.validate_on_submit():
        new_yard = Yard(name=form.name.data, address=form.address.data,
                        capacity=form.capacity.data, company_id=current_user.company_id)
        db.session.add(new_yard)
        db.session.commit()
        return redirect(url_for('Dashboard'))
    return render_template('yard.html', form=form)

@app.route('/admin/users')
@login_required
def AdminUsers():
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    users = User.query.all()

    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:id>')
@login_required
def AdminUser(id):
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))
    
    company = {}
    company_users = 0
    company_yards = 0

    user = User.query.filter_by(id=id).first()
    company = Company.query.filter_by(id=user.company_id).first()
    if company is not None:
        company_users = len(company.users)
        company_yards = len(company.yards)

    return render_template('admin_user.html', user=user, company=company, company_users=company_users, company_yards=company_yards)

@app.route('/admin/user/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def AdminUserDelete(id):
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    if current_user.id == id:
        return redirect(url_for('Dashboard'))

    user_to_delete = User.query.filter_by(id=id).first()
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User deleted')

    return redirect(url_for('AdminUsers'))

@app.route('/admin/user/delete/confirm/<int:id>')
@login_required
def AdminUserConfirmDelete(id):
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    if current_user.id == id:
        return redirect(url_for('Dashboard'))

    user = User.query.filter_by(id=id).first()
    return render_template('confirm_user_delete.html', user=user)

@app.route('/admin/user/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def AdminUserEdit(id):
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    roles = [ {'key': 'Admin', 'value': 0},{'key': 'User', 'value': 1}]

    user_to_edit = User.query.filter_by(id=id).first()
    form = UserForm(obj=user_to_edit)
    form.role.choices = [(role['value'], role['key']) for role in roles]
    companies = Company.query.all()
    form.company_id.choices = [(c.id, c.name) for c in companies]

    if request.method == 'POST' and form.validate_on_submit():
        user_to_edit.username = form.data['username']
        user_to_edit.role = form.data['role']
        user_to_edit.company_id = form.data['company_id']
        db.session.commit()
        return redirect(url_for('AdminUser', id=id))

    return render_template('admin_user_edit.html', form=form)
    

@app.route('/admin/vehicles', methods=['GET', 'POST'])
@login_required
def AdminVehicles():
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    vehicles = Vehicle.query.all()

    return render_template('admin_vehicles.html', vehicles=vehicles)

@app.route('/admin/vehicle/<int:id>', methods=['GET', 'POST'])
@login_required
def AdminVehicleEdit():
    if current_user.role == 1:
        return redirect(url_for('Dashboard'))

    return render_template('admin_vehicle_edit.html')


if __name__ == '__main__':
    app.run(debug=True)
