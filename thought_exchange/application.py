from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///forum.db")

@app.route("/")
@login_required
def index():

    # Selects all posts and comments and renders index.html
    posts = db.execute("SELECT * FROM posts ORDER BY up_votes DESC")
    comments = db.execute("SELECT * FROM comments")
    return render_template("index.html", posts=posts, comments=comments)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():

    # Checks method type
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        # Ensure second password is submitted
        elif not request.form.get("confirmation"):
            return apology("must enter password twice", 403)
        else:
            # Assigns inputs to variables
            username = request.form.get("username")
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")

        # Checks if passwords match
        if password != confirmation:
            return apology("passwords must match", 403)

        # Checks if password is long enough
        if len(password) < 8:
            return apology("password must be atleast 8 characters", 403)

        # Generate hash
        password_hash = generate_password_hash(password)

        # Selects all users
        rows = db.execute("SELECT * FROM users")

        # Checks if username is taken
        for row in rows:
            if row["username"] == username:
                return apology("username is already taken", 403)

        # Inserts into database
        db.execute("INSERT into users (username, hash) VALUES(:username, :p_hash)",
            username=username, p_hash=password_hash)

        # Redirects to index
        flash("Registered!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():

    # Check method type
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)
        # Ensure second password is submitted
        elif not request.form.get("confirmation"):
            return apology("must enter password twice", 403)
        else:
            # Assigns inputs to variables
            username = request.form.get("username")
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")

        # Checks if passwords match
        if password != confirmation:
            return apology("passwords must match", 403)

        # Checks if password is long enough
        if len(password) < 8:
            return apology("password must be atleast 8 characters", 403)
        
        # Generate hash
        password_hash = generate_password_hash(password)

        # Updates password
        db.execute("UPDATE users SET hash = :p_hash WHERE id = :user_id",
                    p_hash=password_hash, user_id=session["user_id"])

        # Redirects to index
        flash("Password Changed!")
        return redirect("/")

    else:

        # Gets username
        row = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])
        username = row[0]["username"]

        # Renders account.html
        return render_template("account.html", username=username)

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():

    # Checks method type
    if request.method == "POST":

        # Gets title and text
        title = request.form.get("title")
        text = request.form.get("text")

        # Inserts title and text into database
        db.execute("INSERT INTO posts (user_id, title, text, up_votes) VALUES (:user, :title, :text, :up_votes)", 
                    user=session["user_id"], title=title, text=text, up_votes=0)

        # Redirects to index
        return redirect("/")

    else:

        # Renders post,html
        return render_template("post.html")

@app.route("/up-vote/<int:post_id>")
@login_required
def up_vote(post_id):
    up_votes = db.execute("SELECT up_votes FROM posts WHERE id = :post_id", post_id=post_id)
    up_votes = up_votes[0]["up_votes"]
    up_votes += 1
    db.execute("UPDATE posts SET up_votes = :up_votes  WHERE id = :post_id", post_id=post_id, up_votes=up_votes)
    return redirect("/")

@app.route("/comment/<int:post_id>", methods=["GET", "POST"])
@login_required
def comment(post_id):

    # Checks request method
    if request.method == "POST":

        # Gets comment text
        text = request.form.get("text")

        # Inserts into comment database
        db.execute("INSERT INTO comments (user_id, post_id, text) VALUES (:user, :post_id, :text)", 
                    user=session["user_id"], post_id=post_id, text=text)

        # Redirects to post
        return redirect("/")

    else:

        # Gets post_id
        # Selects the post
        post = db.execute("SELECT id FROM posts WHERE id = :post_id", post_id=post_id)
        post = post[0]

        # Renders comment.html
        return render_template("comment.html", post=post)
    
@app.route("/posts")
@login_required
def posts():

    # Selects all posts and comments and renders posts.html
    posts = db.execute("SELECT * FROM posts WHERE user_id = :user_id", user_id=session["user_id"])
    comments = db.execute("SELECT * FROM comments")
    # Reders posts
    return render_template("posts.html", posts=posts, comments=comments)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
