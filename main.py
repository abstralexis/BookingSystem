import sqlite3
from uuid import uuid4
import bcrypt 
from email_validator import EmailNotValidError, validate_email
from flask import Flask, request, Response, render_template, redirect, make_response

# Get a new Flask object called App
App = Flask(__name__)

# Get a connection to the sqlite3 database, stored in CWD
def get_connection() -> sqlite3.Connection:
    """Connect to the sqlite database, or create new in CWD"""

    connection: sqlite3.Connection = sqlite3.connect("database.db")
    return connection

# SQL statements used to create the tables if they do not exist
def create_tables(connection: sqlite3.Connection):
    """Creates the tables for the database using the connection"""

    # Get a cursor for the database through the connection
    cursor: sqlite3.Cursor = connection.cursor()
    
    # Execute commands through the cursor
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

# Get a connection, call the create_tables method, then close 
print("Trying connection...")
conn: sqlite3.Connection = get_connection()
print("Creating tables...")
create_tables(conn)
print("Done!")
conn.close()

#------------------------------------------------------------------
# Flask uses a system of having routes. This is the address after
# The domain name (or 127.0.0.1:5000 if stored locally.) You return
# Responses from the server, either using response constructors,
# plain strings, or methods to make render templates using HTML
# that you provide.
#
# In the HTML, you use the function name as the href, e.g.
# <a href="login">Login</login>, rather than the route. The href
# tells the server to use the function with that name, which then
# utilises the App.route() decorator to determine the route.
#------------------------------------------------------------------

# The route / is the "first" page. e.g: "127.0.0.1:5000/"
@App.route("/")
def index():
    return render_template("index.html")

# This is a sample request form method which is not accessible from
# the HTML anymore. Ignore it if you want.
@App.route("/myform", methods=["POST"])
def myform():
    something = request.form["something"]
    print(something)
    return Response("", 200)

# This is the route we take the user to if they press the Login
# hyperlink in index.html.
@App.route("/login")
def loginpage():
    return render_template("login.html")

# This is the route we take the user to once they submit a login
# form. It uses the POST method because GET is highly insecure.
# Its also a lot uglier.
@App.route("/login/submit", methods=["POST"])
def submit_login():
    """
    Process the login submission request from the client and
    return a response - either an error or a redirect to a fail
    page or a redirect to a logged in home page with a session
    cookie that stores the current user's email.
    """
    
    connection = get_connection()

    # Using try and excepts in this code is inherently lazy. 
    # These were used initially to get a working prototype/
    # base page. They could be permissable if the returning
    # of errors was not just chucking some string to the 
    # browser.
    
    # Try to check if the email is valid. The form in HTML
    # should handle it seeing as we set the input type to be
    # email, but this is JIC.
    try:
        emailinfo = validate_email(request.form["email"])
        email = emailinfo.normalized
    except EmailNotValidError as enve:
        return str(enve)
    
    # Get the password from the form in the request passed to
    # this function from the client via the App decorator
    password = request.form["password"]
    
    # This code attempts to get the hashed password for the email
    # we received from the form from the database.
    try:
        # Crucially, this code has had to be edited to avoid Python
        # runtime errors from trying too fetch and then index a 
        # request where no matching email has been found in the
        # database. It probably should be put into its own function
        # as it has to repeat many times. So, we redirect with the
        # fail query in the html address as True.
        cursor = connection.cursor()
        sql_request = cursor.execute("""--sql
            SELECT hashed_password
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()
        
        if sql_request is not None:
            hashed_password = sql_request[0]
        else:
            return redirect("/login?fail=true")

    except sqlite3.Error as e:
        return str(e)

    # Use the bcrypt checkpw function to check if the password input
    # matches the hash for the hashed password. bcrypt handles the
    # maths for the hashing and the salts for us.
    is_correct = bcrypt.checkpw(password.encode(), hashed_password)
    if is_correct:
        # Construct a response to redirect to a logged in home page
        response = make_response(redirect("/home"))
        
        # Set a cookie for the session called userEmail, storing
        # the email, and attach that cookie to the response.
        # This cookie will then be sent back to the server with
        # any following requests to the server in the current browser
        # session. This can then be used to show logged in info
        # sensitive to the account e.g the bookings. This allows
        # For dynamically updating the HTML according to who is
        # logged in. This lets the Jinja template decide whether to 
        # render the "login failed..." message.
        response.set_cookie("userEmail", email)
        
        # Return the response
        return response
    else:
        # Redirect the user back with a fail message
        return redirect("/login?fail=true")

# Routes the user to the signup page.
@App.route("/signup")
def signuppage():
    return render_template("signup.html")

# Submission for the signup. Follows a lot of the same principles
# as login submission.
@App.route("/signup/submit", methods=["POST"])
def submit_signup():
    connection = get_connection()

    # Get static values from the form that we can use as-is
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]

    # Try validating the email again. I believe this library would
    # be using a mix of regex and other algorithms.
    try:
        emailinfo = validate_email(request.form["email"])
        email = emailinfo.normalized
    except EmailNotValidError as enve:
        return str(enve)
    
    # Generate a salt for the hashed password. A salt is a random
    # value that is appended so that the hash outputs a different 
    # value, even when the password is the same. This secures
    # the database from a rainbow-table (precalculated passwords for
    # the hashing algorithm) attack should the table be breached.
    # In addition, bcrypt does not store the salt alongside the
    # passwords, making it more secure than other encryption
    # libraries. If it was stored alongside it and an attacker
    # got their hands on the database, they could brute force 
    # passwords using the salt they acquired.
    salt = bcrypt.gensalt()
    
    # Get password input and then hash it using the salt.
    password = request.form["password"]
    password = bcrypt.hashpw(password.encode(), salt)

    # Get a random UUID.
    uuid = str(uuid4())

    # Try to insert the values needed into the database for the 
    # new user. Something cool is that the function seems to 
    # sanitise against sql-injection automatically.
    try:
        cursor = connection.cursor()
        cursor.execute(
            """--sql
                INSERT INTO users
                VALUES (?, ?, ?, ?, ?);
            """, 
            [uuid, email, first_name, last_name, password]
        )
        # Insert operations require the connection to be committed.
        connection.commit()
        connection.close()
    except sqlite3.Error as e:
        return redirect("/signup?fail=true")

    # Redirect to the login page on a successful signup.
    return redirect("/login")

# Im not sure if POST is needed here - just GET which is the methods
# default so the argument might not be needed.
@App.route("/home", methods=["GET", "POST"])
def home():
    return render_template("home.html")

# The page for making a booking after logging in
@App.route("/makebooking")
def makebooking():
    return render_template("makebooking.html")

# This is the method for viewing the bookings that the current user
# has made. It returns a render template and an extra keyword argument
# called data. This kwarg is used in the HTML template using
# Jinja syntax to dynamically populate a table.
@App.route("/viewbookings")
def viewbookings():
    connection = get_connection()
    
    # Get the userEmail cookie
    email: str = request.cookies.get("userEmail")

    # Get the user UUID from the database based off of the email.
    # We do not need to validate the email again, as it has already
    # been validated by our server.
    try:
        cursor = connection.cursor()
        sql_request = cursor.execute("""--sql
            SELECT uuid  
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()

        if sql_request is not None:
            booker_id = sql_request[0]
        else:
            return redirect("/viewbookings?fail=true")

        cursor.close()
    except sqlite3.Error as e:
        return redirect("/viewbookings?fail=true")

    # Using users.uuid, select the start and end times for all 
    # bookings in bookings where the uuid from users matches the
    # booker_id foreign key in bookings.
    try:
        cursor = connection.cursor()
        data = cursor.execute("""--sql
                SELECT start_time, end_time
                FROM bookings
                WHERE booker_id = ?
        """, [booker_id]).fetchall()
        # Send the data alongside the HTML template.
        return render_template("viewbookings.html", data=data)
    except sqlite3.Error as e:
        return str(e)

# This is the function for submitting a booking. This once
# again uses previous principles, including accessing the cookie.
@App.route("/makebooking/submit", methods=["POST"])
def submitbooking():
    connection = get_connection()

    email: str = request.cookies.get("userEmail")
    start = request.form["starttime"]
    end = request.form["endtime"]

    try:
        cursor = connection.cursor()
        sql_request = cursor.execute("""--sql
            SELECT uuid  
            FROM users 
            WHERE email = ?
        """, [email]).fetchone()

        if sql_request is not None:
            booker_id = sql_request[0]
        else:
            return redirect("/makebooking?fail=true")
    except sqlite3.Error as e:
        return redirect("/makebooking?fail=true")
    
    # This gets the number of clashes with the proposed booking time
    # by selecting the entry (uuid only to be lightweight) of any
    # booking that overlaps. When two bookings, P and Q DONT overlap,
    # we have two events which both must be true: Pstart > Qend, AND
    # Pend < Qstart. Lets call these events A and B respectively.
    # As A AND B represents the non-overlapping case, thus we need 
    # NOT(A AND B) to represent the overlapping case.
    # Using De Morgan's Law, NOT(A AND B) becomes NOT(A) OR NOT(B).
    # NOT(A) becomes Pstart <= Qend and NOT(B) becomes Pend >= Qstart.
    try:
        cursor = connection.cursor()
        num_clashes = len(cursor.execute("""--sql
            SELECT uuid 
            FROM bookings
            WHERE (end_time >= ?) AND (? >= start_time)
        """, [start, end]).fetchall())
        cursor.close()
    except sqlite3.Error as e:
        return str(e)
    
    if num_clashes > 0:
        return redirect("/makebooking?fail=true")
    
    # Finally, if none of the previous guard clauses have triggered,
    # i.e. we have not returned early, try to insert the booking
    # into the table.
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
        redirect("/makebooking?fail=true")

    # Redirect to the home page on a booking success.
    return redirect("/home")

if __name__ == "__main__":
    #main()
    # Run our app in debug mode (not to be used in production)
    App.run(debug=True)