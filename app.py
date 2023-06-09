import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date
from helpers import login_required, apology

# Custom filter
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure app to use SQLite database
db = SQL("sqlite:///database.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        admin = request.form.get("admin")
        like = request.form.get("like")
        if admin:
            db.execute("DELETE FROM images WHERE id =  ?", admin)
            db.execute("DELETE FROM like WHERE image_id =  ?", admin)
        if like:
            checkliked = db.execute("SELECT * FROM like WHERE image_id = ? AND user_id = ?", like, session["user_id"])
            if not checkliked:
                db.execute("UPDATE images SET likes = likes + 1 WHERE id = ?", like)
                db.execute("INSERT INTO like (image_id, user_id) VALUES (?, ?)", like, session["user_id"])
    if session["user_id"] == 1:
        admin = 1
    else:
        admin = 0
    rows = db.execute("SELECT * FROM images ORDER BY id DESC")
    alreadyliked = db.execute("SELECT image_id FROM like WHERE user_id = ?", session["user_id"])
    for row in rows:
        row['colour'] = 0
        for like in alreadyliked:
            if row['id'] == like['image_id']:
                row['colour'] = 1
    """Check for total amount likes for cats and dogs"""
    dog = db.execute("SELECT SUM(likes) FROM images WHERE animal = ?", "dog")
    cat = db.execute("SELECT SUM(likes) FROM images WHERE animal = ?", "cat")
    return render_template("home.html", images=rows, admin=admin, cat=cat[0]['SUM(likes)'], dog=dog[0]['SUM(likes)'])
    

@app.route("/post", methods=["GET", "POST"])
def post():
    if request.method == "POST":
        image = request.form.get("image")
        animal = request.form.get("animal")
        if not image:
            return apology("must provide image address", 403)
        elif not animal:
            return apology("must provide animal type", 403)
        elif animal == "error":
            return apology("must be cat or dog", 403)
        else:
            db.execute("INSERT INTO images (address, username, likes, animal) VALUES (?, ?, 0, ?)", image, session["username"], animal)
            return redirect("/")
    else:
        return render_template("/post.html")
    
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    
    
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Ensure username was submitted
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match", 400)
        for i in range(int(db.execute("SELECT COUNT(username) FROM users")[0]['COUNT(username)'])):
            if request.form.get("username") in db.execute("SELECT username FROM users")[i]['username']:
                return apology("Username already exists")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"),
                        generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))
            return redirect("/")
    else:
        return render_template("register.html")
    

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")