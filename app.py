from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from models import db, User, Todo
from forms import RegistrationForm, LoginForm, TodoForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.route('/')
def home():
    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created. You can now log in!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('todo'))
        else:
            flash('Login failed. Please check your username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo():
    form = TodoForm()
    if form.validate_on_submit():
        task = Todo(task=form.task.data, user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('todo'))

    todos = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('todo.html', form=form, todos=todos)

@app.route('/delete/<int:todo_id>')
@login_required
def delete(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id == current_user.id:
        db.session.delete(todo)
        db.session.commit()
    return redirect(url_for('todo'))

@app.route('/update/<int:todo_id>', methods=['POST'])
@login_required
def update(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id == current_user.id:
        todo.task = request.form['task']
        db.session.commit()
    return redirect(url_for('todo'))

if __name__ == "__main__":
    app.run(debug=True)
