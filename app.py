import os
from flask import Flask, request, redirect, session, url_for, render_template_string
from dotenv import load_dotenv
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

url = os.environ["SUPABASE_URL"]
key = os.environ["SUPABASE_KEY"]

supabase: Client = create_client(url, key)


@app.route("/")
def index():
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        employee_id = request.form.get("employee_id", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([employee_id, first_name, last_name, email, password, confirm_password]):
            message = "Please fill in all fields."
        elif password != confirm_password:
            message = "Passwords do not match."
        else:
            existing = supabase.table("app_user").select("*").eq("email", email).execute()

            if existing.data:
                message = "An account with that email already exists."
            else:
                password_hash = generate_password_hash(password)

                response = supabase.table("app_user").insert({
                    "employee_id": employee_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "password_hash": password_hash,
                    "role": "analyst",
                    "employee_id_verified": False,
                    "is_active": True
                }).execute()

                if response.data:
                    message = "Account created. Please ask an admin to verify your employee ID before login."
                else:
                    message = "Error creating account."

    return render_template_string("""
    <html>
    <head><title>Create New User</title></head>
    <body>
        <h1>Create New User</h1>
        <form method="post">
            <p>Employee ID: <input type="text" name="employee_id"></p>
            <p>First Name: <input type="text" name="first_name"></p>
            <p>Last Name: <input type="text" name="last_name"></p>
            <p>Email: <input type="email" name="email"></p>
            <p>Password: <input type="password" name="password"></p>
            <p>Confirm Password: <input type="password" name="confirm_password"></p>
            <p><button type="submit">Create User</button></p>
        </form>

        <p style="color:red;">{{ message }}</p>
        <p><a href="{{ url_for('login') }}">Back to Login</a></p>
    </body>
    </html>
    """, message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        response = supabase.table("app_user").select("*").eq("email", email).execute()
        users = response.data or []

        if not users:
            message = "No user found with that email."
        else:
            user = users[0]

            if not user.get("is_active", True):
                message = "This account is inactive."
            elif not user.get("employee_id_verified", False):
                message = "This employee ID has not been verified yet."
            elif not check_password_hash(user["password_hash"], password):
                message = "Incorrect password."
            else:
                session["user_email"] = user["email"]
                session["user_name"] = f"{user['first_name']} {user['last_name']}"
                session["user_role"] = user["role"]
                session["employee_id"] = user["employee_id"]
                return redirect(url_for("dashboard"))

    return render_template_string("""
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Bank Fraud Portal Login</h1>
        <form method="post">
            <p>Email: <input type="email" name="email"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><button type="submit">Login</button></p>
        </form>

        <p style="color:red;">{{ message }}</p>
        <p><a href="{{ url_for('register') }}">Create New User</a></p>
    </body>
    </html>
    """, message=message)


@app.route("/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    return render_template_string("""
    <html>
    <head><title>Dashboard</title></head>
    <body>
        <h1>Dashboard</h1>
        <p>Welcome, {{ session['user_name'] }}</p>
        <p>Employee ID: {{ session['employee_id'] }}</p>
        <p>Role: {{ session['user_role'] }}</p>

        <ul>
            <li><a href="{{ url_for('view_customers') }}">View Customers</a></li>
            <li><a href="{{ url_for('logout') }}">Logout</a></li>
        </ul>
    </body>
    </html>
    """)


@app.route("/customers")
def view_customers():
    if "user_email" not in session:
        return redirect(url_for("login"))

    response = supabase.table("customer").select("*").execute()
    customers = response.data or []

    return render_template_string("""
    <html>
    <head><title>Customers</title></head>
    <body>
        <h1>Customers</h1>
        <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>

        <table border="1" cellpadding="8">
            <tr>
                <th>customer_id</th>
                <th>first_name</th>
                <th>last_name</th>
                <th>email</th>
                <th>phone</th>
            </tr>
            {% for c in customers %}
            <tr>
                <td>{{ c.customer_id }}</td>
                <td>{{ c.first_name }}</td>
                <td>{{ c.last_name }}</td>
                <td>{{ c.email }}</td>
                <td>{{ c.phone }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """, customers=customers)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
