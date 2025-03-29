from datetime import date
from flask import request,Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager=LoginManager()
login_manager.init_app(app)


# load_user
@login_manager.user_loader
def load_user(userId):
    return db.get_or_404(User,userId)


#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function
 

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# TODO: Create a User table for all your registered users. 
class User(UserMixin,db.Model): #Parent
    __tablename__="users"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    email:Mapped[str]=mapped_column(String(100),unique=True)
    password:Mapped[str]=mapped_column(String(100))
    name:Mapped[str]=mapped_column(String(100))

    #This will act like a List of BlogPost objects attached to each User. 
    #The "author" refers to the author property in the BlogPost class.
    posts=relationship("BlogPost",back_populates="author")

    #Relationship to Comment (one to many)
    comments=relationship("Comment",back_populates="comment_author")


# CONFIGURE TABLES
class BlogPost(db.Model):   #Child
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

     # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    #***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


# Comment Table
class Comment(db.Model):
    __tablename__="comments"
    ip:Mapped[int]=mapped_column(Integer,primary_key=True)
    text:Mapped[str]=mapped_column(String(250),nullable=False)

     #*******Add child relationship*******#
    #"users.id" The users refers to the tablename of the Users class.
    #"comments" refers to the comments property in the User class.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    #***************Child Relationship*************#
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")



with app.app_context():
    db.create_all()
    # new_user=User(
    #     name="Prashant Kumar",
    #     email="pkritwan1020@gmail.com",
    #     password=generate_password_hash(password="12345",method="pbkdf2:sha256",salt_length=8)
    # )
    # db.session.add(new_user)
    # db.session.commit()


gravtar=Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=['POST','GET'])
def register():
    message=None
    form=RegisterForm()
    if request.method=='POST':
        email=form.email.data

        #Search this data is exist in Database or not
        result=db.session.execute(db.select(User).where(User.email==email))
        #Get the user which have same email
        user=result.scalar()
        if user:
            flash("You've already signed up with email, log in instead!","warning")
            # Redirect user to login page
            return redirect(url_for('login'))
        #If user doesn't exist in data then get the information
        name=form.name.data
        password=form.password.data
        #Generate pass in hash
        password=generate_password_hash(password=password,method='pbkdf2:sha256',salt_length=8)

        # Add extracted data to database
        new_user=User(
            name=name,
            email=email,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        # Makes current_user available throughout the session.
        # Allows access to @login_required routes.
        return redirect(url_for('get_all_posts'))
    
    return render_template("register.html",form=form,logged_in=current_user.is_authenticated)




# TODO: Retrieve a user from the database based on their email. 
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    # message=None
    if request.method=='POST':
        email=form.email.data
        password=form.password.data

        #Check user via email 
        result=db.session.execute(db.select(User).where(User.email==email))
        user=result.scalar()

        #If not found user behalf on its email
        if not user:
            # message="This email does not exist, please try again."
            flash("This email does not exist, please try again.","danger")
        #User is from database then check the password
        elif check_password_hash(user.password,password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        #User's password is not same
        else:
            flash("Password incorrect, please try again.","danger")

        # return render_template("login.html",form=form)
        
    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    # logged_in=False
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()


    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated,current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    comment_form=CommentForm()

    #Only if when user write somthing i comments sections
    if comment_form.validate_on_submit():
        # Only if current user logged in the account
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        #Else he/She logged in Lte them permisson to comment on the post
        new_comment=Comment(
            text=comment_form.commentBody.data,
            comment_author=current_user,
            parent_post=requested_post
        ) 
        db.session.add(new_comment)
        db.session.commit()


    return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated,form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
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
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True,logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html",logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html",logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
