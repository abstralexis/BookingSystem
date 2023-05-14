import sqlite3
import requests
from uuid import uuid4
import bcrypt 
from email_validator import EmailNotValidError, validate_email
from flask import Flask, request, Response, render_template, redirect, make_response

App = Flask(__name__)

def get_connection() -> sqlite3.Connection:
    """Connect to the sqlite database, or create new in CWD"""

    connection: sqlite3.Connection = sqlite3.connect("database.db")
    return connection

def create_tables(connection: sqlite3.Connection):
    """Creates the tables for the database using the connection"""

    cursor: sqlite3.Cursor = connection.cursor()
    cursor.execute("""--sql
        CREATE TABLE IF NOT EXISTS users (
            uuid UUID UNIQUE NOT NULL,
            email VARCHAR UNIQUE NOT NULL,
            first_name VARCHAR NOT NULL,
            last_name VARCHAR NOT NULL,
            hashed_password VARCHAR NOT NULL
        )
    """)
    cursor.execute("""--sql
        CREATE TABLE IF NOT EXISTS bookings (
            uuid UUID NOT NULL,
            booker_id UUID NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE NOT NULL,
            FOREIGN KEY (booker_id) REFERENCES users(uuid)
        )
    """)

print("Trying connection...")
conn: sqlite3.Connection = get_connection()
print("Creating tables...")
create_tables(conn)
print("Done!")
conn.close()

@App.route("/")
def index():
    return render_template("index.html")

@App.route("/myform", methods=["POST"])
def myform():
    something = request.form["something"]
    print(something)
    return Response("", 200)

@App.route("/login")
def loginpage():
    return render_template("login.html")

@App.route("/signup/submit", methods=["POST"])
def submit_signup():
    connection = get_connection()

    print(request.form)
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]

    try:
        emailinfo = validate_email(request.form["email"])
        email = emailinfo.normalized
    except EmailNotValidError as enve:
        return str(enve)
    
    salt = bcrypt.gensalt()
    password = request.form["password"]
    password = bcrypt.hashpw(password.encode(), salt)

    uuid = str(uuid4())

    try:
        cursor = connection.cursor()
        cursor.execute(
            """--sql
                INSERT INTO users 
                VALUES (?, ?, ?, ?, ?);
            """, 
            [uuid, email, first_name, last_name, password]
        )
        connection.commit()
        connection.close()
    except sqlite3.Error as e:
        return str(e)

    return redirect("/login")

@App.route("/login/submit", methods=["POST"])
def submit_login():
    connection = get_connection()

    try:
        emailinfo = validate_email(request.form["email"])
        email = emailinfo.normalized
    except EmailNotValidError as enve:
        return str(enve)
    
    password = request.form["password"]
    
    try:
        cursor = connection.cursor()
        hashed_password = cursor.execute("""--sql
            SELECT hashed_password
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()[0]
    except sqlite3.Error as e:
        return str(e)

    is_correct = bcrypt.checkpw(password.encode(), hashed_password)
    if is_correct:
        response = make_response(redirect("/home"))
        response.set_cookie("userEmail", email)
        return response
    else:
        return redirect("/login/fail")
    
@App.route("/home", methods=["GET", "POST"])
def home():
    return render_template("home.html")
    
@App.route("/login/fail", methods=["GET", "POST"])
def login_fail():
    return render_template("loginfail.html")
 
@App.route("/signup")
def signuppage():
    return render_template("signup.html")

@App.route("/makebooking")
def makebooking():
    return render_template("makebooking.html")

@App.route("/viewbookings")
def viewbookings():
    connection = get_connection()
    email: str = request.cookies.get("userEmail")

    try:
        cursor = connection.cursor()
        booker_id = cursor.execute("""--sql
            SELECT uuid  
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()[0] 
        cursor.close()
    except sqlite3.Error as e:
        return str(e)

    try:
        cursor = connection.cursor()
        data = cursor.execute("""--sql
                SELECT start_time, end_time
                FROM bookings
                WHERE booker_id = ?
        """, [booker_id]).fetchall()
        return render_template("viewbookings.html", data=data)
    except sqlite3.Error as e:
        return str(e)

@App.route("/makebooking/submit", methods=["POST"])
def submitbooking():
    connection = get_connection()

    email: str = request.cookies.get("userEmail")
    start = request.form["starttime"]
    end = request.form["endtime"]

    try:
        cursor = connection.cursor()
        booker_id = cursor.execute("""--sql
            SELECT uuid  
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()[0] 
        cursor.close()
    except sqlite3.Error as e:
        return str(e)
    
    try:
        cursor = connection.cursor()
        num_clashes = len(cursor.execute("""--sql
            SELECT uuid 
            FROM bookings
            WHERE (end_time >= ?) AND (? >= start_time)
        """, [start, end]).fetchall())
        print(num_clashes)
        cursor.close()
    except sqlite3.Error as e:
        return str(e)
    
    if num_clashes > 0:
        return redirect("/makebooking/fail-overlap")
    
    try:
        uuid = str(uuid4())
        cursor = connection.cursor()
        cursor.execute("""--sql
            INSERT INTO bookings
            VALUES (?, ?, ?, ?)
        """, [uuid, booker_id, start, end])
        connection.commit()
        connection.close()
    except sqlite3.Error as e:
        return str(e)

    return redirect("/home")

@App.route("/makebooking/fail-overlap")
def makebookingfailoverlap():
    return render_template("makebookingfailoverlap.html")

if __name__ == "__main__":
    #main()
    App.run(debug=True)