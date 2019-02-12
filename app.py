from flask import Flask, render_template, request, session, logging, url_for, redirect, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker
from functools import wraps

from passlib.hash import sha256_crypt
engine = create_engine("mysql+pymysql://root:1234567@localhost/register")
db=scoped_session(sessionmaker(bind=engine))
app = Flask(__name__)

f = 'election_vote.txt'
f1 = 'social_vote.txt'

poll_data = {
   'fields1'   : ['BJP', 'CONGRESS', 'AAP', 'NOTA'],
   'fields2'   : ['Facebook', 'Twitter', 'Instagram', 'Snapchat']
}

@app.route("/")
def home():
    if 'log' in session:
        return render_template("dashboard.html")
    else:
        return render_template("home.html")

@app.route("/register",methods=["Get","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        secure_password = sha256_crypt.encrypt(str(password))
        usernamedata = db.execute("SELECT username FROM users WHERE username=:username",{"username":username}).fetchone()
        if usernamedata is not None:
            for username in usernamedata:
                if username == username:
                    flash("Username already taken","danger")
                    return redirect(url_for('register'))
        if password == confirm:
            db.execute("INSERT INTO users(name, username, password) VALUES(:name,:username,:password)",
                                        {"name":name,"username":username,"password":secure_password})
            db.commit()
            flash("You successful registered and can login","success")
            return redirect(url_for('login'))
        else:
            flash("Password does not match","danger")
            return render_template("register.html")

    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        usernamedata = db.execute("SELECT username FROM users WHERE username=:username",{"username":username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username=:username",{"username":username}).fetchone()
        if usernamedata is None:
            flash("No username","danger")
            return render_template("login.html")
        else:
            for password_data in passworddata:
                if sha256_crypt.verify(password,password_data):
                    session["log"] = True
                    flash("You are now logged in","success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("incorrect password","danger")
                    return render_template("login.html")
    return render_template("login.html")

def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'log' in session:
            return test(*args, **kwargs)
        else:
            flash("You need to login first.")
            return redirect(url_for('login'))
    return wrap

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You are now logged out","success")
    return redirect(url_for('login'))

@app.route("/pole1")
def pole1():
    if 'log' in session:
        return render_template("pole1.html")
    else:
        flash("You need to login first")
        return redirect(url_for('login'))

@app.route("/pole2")
def pole2():
    if 'log' in session:
        return render_template("pole2.html")
    else:
        flash("You need to login first")
        return redirect(url_for('login'))

@app.route("/thanks")
def thanks():
    vote = request.args.get('value')
    out = open(f,'a')
    out.write( vote + '\n')
    out.close()
    return render_template("thanks.html")

@app.route("/thanks1")
def thanks1():
    vote = request.args.get('value')
    out = open(f1,'a')
    out.write( vote + '\n')
    out.close()
    return render_template("thanks.html")

@app.route("/results")
def results(chartID = 'chart_ID', chart_type = 'bar', chart_height= 500):
    if 'log' in session:
        votes = {}
        votes1 = {}
        for q in poll_data['fields1']:
            votes[q] = 0
        for w in poll_data['fields2']:
            votes1[w] = 0
        q  = open(f, 'r')
        w = open(f1, 'r')
        for line in q:
            vote = line.rstrip("\n")
            votes[vote] += 1
        for line in w:
            vote = line.rstrip("\n")
            votes1[vote] += 1
        chart = {"renderTo": chartID, "type": chart_type, "height": chart_height,}
        series = [{"name": 'Hello', "data": [1]}, {"name": 'Label2', "data": [4]}]
        title = {"text": 'My Title'}
        xAxis = {"categories": ['Party']}
        yAxis = {"title": {"text": 'Votes'}}
        return render_template('results.html', votes=votes, votes1=votes1, chartID=chartID, chart=chart, series=series, title=title, xAxis=xAxis, yAxis=yAxis)
    else:
        flash("You need to login first","danger")
        return redirect(url_for('login'))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__=="__main__":
    app.secret_key="1234567abjpt2633c"
    app.run(debug=True)
