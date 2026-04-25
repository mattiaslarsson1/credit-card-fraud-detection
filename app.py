import os
from flask import Flask, request, redirect, session, url_for, render_template
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

@app.route("/dev-login")
def dev_login():
    session["user_email"] = "dev@test.com"
    session["user_name"] = "Dev User"
    session["user_role"] = "admin"
    session["employee_id"] = "EMP001"
    return redirect(url_for("dashboard"))

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
            employee_check = supabase.table("employees").select("employee_id").eq("employee_id", employee_id).execute()

            if not employee_check.data:
                message = "Employee ID not found. Please contact your administrator."
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

    return render_template("register.html", message=message)


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

    return render_template("login.html", message=message)


@app.route("/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/customers")
def view_customers():
    if "user_email" not in session:
        return redirect(url_for("login"))

    response = supabase.table("customer").select("*").execute()
    customers = response.data or []

    return render_template("customers.html", customers=customers)


@app.route("/customers/add", methods=["GET", "POST"])
def add_customer():
    if "user_email" not in session:
        return redirect(url_for("login"))

    message = ""

    # Fetch banks for the dropdown
    banks = supabase.table("bank").select("bank_id, bank_name").execute().data or []

    if request.method == "POST":
        bank_id = request.form.get("bank_id", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        address = request.form.get("address", "").strip()

        if not all([bank_id, first_name, last_name, email]):
            message = "Please fill in all required fields."
        else:
            response = supabase.table("customer").insert({
                "bank_id": int(bank_id),
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "phone": phone or None,
                "date_of_birth": date_of_birth or None,
                "address": address or None
            }).execute()

            if response.data:
                return redirect(url_for("view_customers"))
            else:
                message = "Error adding customer."

    return render_template("add_customer.html", banks=banks, message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
