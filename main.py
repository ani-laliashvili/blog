from flask import Flask, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import SubmitField, BooleanField, StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps
import os
from dotenv import load_dotenv
from datetime import datetime

year = datetime.now().year

app = Flask(__name__)
if os.environ.get('SECRET_KEY') != None:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
else:
    # Connect the path with the '.env' file name
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(dotenv_path=os.path.join(BASEDIR, '.env'))
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db").replace('postgres', 'postgresql')

ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #Parent relationship
    comments = relationship('Comment', back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="comment_author")

class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Child relationship
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")

    text = db.Column(db.Text, nullable=False)

db.create_all()

class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(message='Field required'), Email(message='Invalid email address')])
    password = PasswordField(label='Password', validators=[DataRequired(message='Field required'), Length(min=8, message='Password must be at least 8 characters')])
    name = StringField(label='Name', validators=[DataRequired(message='Field required')])
    submit = SubmitField(label='SIGN ME UP!')

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(message='Field required'), Email(message='Invalid email address')])
    password = PasswordField(label='Password', validators=[DataRequired(message='Field required'), Length(min=8, message='Password must be at least 8 characters')])
    submit = SubmitField(label='LET ME IN!')

class CommentForm(FlaskForm):
    body = StringField(label='Comment', validators=[DataRequired()])
    submit = SubmitField(label='SUBMIT COMMENT')

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, year=year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if not User.query.filter_by(email=request.form.get('email')).first():
            hash_and_salted_password = generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(email=request.form.get('email'),
                            password=hash_and_salted_password,
                            name=request.form.get('name'))
            db.session.add(new_user)
            db.session.commit()
        else:
            flash("You've already signed up with that email, log in instead.")
            return redirect(url_for('login', year=year))

        return redirect(url_for('login', year=year))


    return render_template("register.html", form=register_form, year=year)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if not user:
            flash('User does not exist. Please register.')
            return redirect(url_for('register', year=year))
        elif check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            next = request.args.get('next')
            return redirect(url_for('get_all_posts', year=year))
        else:
            flash('Password incorrect. Please try again.')
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form, year=year)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', year=year))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    if request.method == 'POST' and current_user.is_authenticated:
        new_comment = Comment(post_id = post_id,
                              author_id = current_user.id,
                              text=form.body.data)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id, year=year))
    elif request.method == 'POST':
        return redirect(url_for('login', year=year))

    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form, comments=requested_post.comments, year=year)


@app.route("/about")
def about():
    return render_template("about.html", year=year)


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        return render_template("contact.html", year=year)
    elif request.method == 'GET':
        return render_template("contact.html", year=year)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", year=year))
    return render_template("make-post.html", form=form, year=year)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, year=year))

    return render_template("make-post.html", form=edit_form, year=year)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'), year=year)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
