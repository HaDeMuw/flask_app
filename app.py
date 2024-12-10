from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Создаем экземпляр SQLAlchemy
db = SQLAlchemy()

# Создаем экземпляр LoginManager
login_manager = LoginManager()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    tickets = db.relationship('Ticket', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    car_number = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='new')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Телефон', validators=[DataRequired()])
    full_name = StringField('Полное имя', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class CreateTicketForm(FlaskForm):
    car_number = StringField('Номер автомобиля', validators=[DataRequired()])
    description = TextAreaField('Описание нарушения', validators=[DataRequired()])
    submit = SubmitField('Создать заявление')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    
    # Инициализируем расширения
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            new_user = User(username=form.username.data, email=form.email.data, phone=form.phone.data, full_name=form.full_name.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Аккаунт успешно создан!', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Не удалось войти. Проверьте имя пользователя и пароль', 'danger')
        return render_template('login.html', form=form)

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        tickets = Ticket.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', tickets=tickets)

    @app.route('/create_ticket', methods=['GET', 'POST'])
    @login_required
    def create_ticket():
        form = CreateTicketForm()
        if form.validate_on_submit():
            new_ticket = Ticket(car_number=form.car_number.data, description=form.description.data, author=current_user)
            db.session.add(new_ticket)
            db.session.commit()
            flash('Ваше заявление успешно создано!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('create_ticket.html', form=form)

    @app.route('/admin', methods=['GET', 'POST'])
    @login_required
    def admin_panel():
        if current_user.username != 'copp' or not current_user.check_password('password'):
            flash('Доступ запрещен!', 'danger')
            return redirect(url_for('login'))
        
        tickets = Ticket.query.all()
        if request.method == 'POST':
            ticket_id = request.form.get('ticket_id')
            status = request.form.get('status')
            ticket = Ticket.query.get(ticket_id)
            if ticket:
                ticket.status = status
                db.session.commit()
                flash('Статус заявления обновлен!', 'success')
        return render_template('admin_panel.html', tickets=tickets)

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)