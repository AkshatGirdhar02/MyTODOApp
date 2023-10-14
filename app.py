from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
# To connect app to database we use
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
app.config['SQLALCHEMY_BINDS'] = {'todo_database': "sqlite:///todo.db"}
# To secure the session we create a secret key
app.config['SECRET_KEY'] = 'thisisasecretkey'
# To create a database instance we use
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    flash("Please log in !!")
    return redirect(url_for('login'))
# Create columns for database


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    todos = db.relationship('Todo', backref='user')


class Todo(db.Model):
    # __bind_key__='todo_database'
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # What should get printed when we call the object of Todo class

    def __repr__(self) -> str:
        return f"{self.sno}-{self.title}"


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=5, max=30)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=15)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    # To verify that same username does not exist,we will create a function
    # def validate_username(self, username):
    #     existing_username = User.query.filter_by(
    #         username=username.data).first()
    #     if existing_username:
    #         raise ValidationError("That username already exists! Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=5, max=30)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=15)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class TODOForm(FlaskForm):
    title = StringField(validators=[InputRequired(), Length(
        min=5, max=200)], render_kw={"placeholder": "Enter TODO Title"})
    desc = StringField(validators=[InputRequired(), Length(
        min=5, max=500)], render_kw={"placeholder": "Enter TODO Description"})
    submit = SubmitField("Add TODO")


@app.route('/')
def homePage():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/dashboard')
            else:
                flash("Invalid username or password!!")
                return redirect('/login')
        else:
            flash("User does not exists!!")
            return redirect('/login')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')
    # return render_template('base.html')


@app.route('/register', methods=['GET', 'POST'])
def registerPage():
    form = RegisterForm()
    if request.method == 'POST':
        if form.is_submitted():
            existing_username = User.query.filter_by(
                username=form.username.data).first()
            if existing_username:
                if bcrypt.check_password_hash(existing_username.password,form.password.data):
                    flash("User already exists!!")
                else:
                    flash("Username already taken! Please choose another one")
                    return redirect('/register')
            else:
                hashed_password = bcrypt.generate_password_hash(form.password.data)
                new_user = User(username=form.username.data,
                                password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
            return redirect('/dashboard')
    return render_template('register.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = TODOForm()
    if request.method == 'POST':
        # print(request.form['title'])#Here we have to specify the name of the field that we have specified in the form
        title = request.form['title']
        desc = request.form['desc']
        user_id = current_user.id
        
        if not title or not desc:
            flash("Title and description cannot be empty! Please fill both the fields")
        else:
            todo = Todo(title=title, desc=desc, user_id=user_id)
            # To add instance in db
            db.session.add(todo)
            # To make it permanent in db
            db.session.commit()
            return redirect('/viewTodo')
    # whenver user comes to home page a new instance with the following details will be created
    # Define the values of instance
    # todo=Todo(title="First Todo",desc="Start investing in stock market")
    # #To add instance in db
    # db.session.add(todo)
    # db.session.commit()
    # allTodo = Todo.query.all()
    allTodo = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('todo_main.html', allTodo=allTodo)
    # return render_template('dashboard.html')


@app.route('/viewTodo')
def viewTodo():
    # allTodo = Todo.query.all()
    allTodo = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('todo_view.html', allTodo=allTodo)


@app.route('/update/<int:sno>', methods=['GET', 'POST'])
def update(sno):
    todo = Todo.query.filter_by(sno=sno).first()  # Get the specific to-do item

    if not todo:
        # Handle the case where the specified to-do item doesn't exist
        return "Todo not found"

    # Ensure that the user can only update their own to-do items
    if todo.user_id != current_user.id:
        return "You don't have permission to update this to-do item"

    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        # Select the first record with the given sno to update it
        # todo = Todo.query.filter_by(sno=sno).first()
        todo.title = title
        todo.desc = desc
        db.session.add(todo)
        db.session.commit()
        return redirect('/dashboard')
    # Select the first record with the given sno to update it
    todo = Todo.query.filter_by(sno=sno).first()
    return render_template('todo_update.html', todo=todo)


@app.route("/delete/<int:sno>")
def delete(sno):
    # Search the first record with the given sno and delete it
    todo = Todo.query.filter_by(sno=sno).first()

    if not todo:
        # Handle the case where the specified to-do item doesn't exist
        return "Todo not found"

    # Ensure that the user can only delete their own to-do items
    if todo.user_id != current_user.id:
        return "You don't have permission to delete this to-do item"

    # Delete a record
    db.session.delete(todo)
    # Make change final
    db.session.commit()
    return redirect('/viewTodo')
if __name__=="__main__":
    app.run(debug=False,host='0.0.0.0')
