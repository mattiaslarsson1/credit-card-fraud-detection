import os
from flask import Flask, request, redirect, session, url_for, render_template, render_template_string
from dotenv import load_dotenv
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["SESSION_PERMANENT"] = False

url = os.environ["SUPABASE_URL"]
key = os.environ["SUPABASE_SERVICE_KEY"]

supabase: Client = create_client(url, key)
def require_login():
    return "user_email" in session


SECURITY_DEPARTMENT = "security"

def get_role_for_employee(employee_id):
    if not employee_id:
        return "analyst"
    employee = (
        supabase.table("employees")
        .select("department")
        .eq("employee_id", employee_id)
        .execute()
        .data
    )
    if not employee:
        return "analyst"
    department = (employee[0].get("department") or "").strip().lower()
    return "admin" if department == SECURITY_DEPARTMENT else "analyst"


def require_admin():
    return "user_email" in session and session.get("user_role") == "admin"


def safe_get(row, *keys, default=""):
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


def get_transactions_data():
    candidate_tables = ["transactions", "transaction", "credit_card_transaction"]

    last_error = None
    for table_name in candidate_tables:
        try:
            response = supabase.table(table_name).select("*").execute()
            return table_name, response.data or [], None
        except Exception as e:
            last_error = str(e)

    return None, [], last_error

HIGH_RISK_AMOUNT_THRESHOLD = 500
HIGH_RISK_ALERT_STATUSES = {"open", "investigating"}
HIGH_RISK_TRANSACTION_STATUSES = {"flagged"}


def get_high_risk_transactions():
    transaction_response = supabase.table("transaction").select("*").execute()
    transactions = transaction_response.data or []

    alert_response = supabase.table("fraud_alert").select("*").execute()
    alerts = alert_response.data or []
    active_alerts_by_transaction_id = {}

    for alert in alerts:
        alert_status = (alert.get("alert_status") or "").lower()
        if alert_status in HIGH_RISK_ALERT_STATUSES:
            active_alerts_by_transaction_id[alert.get("transaction_id")] = alert

    merchant_response = supabase.table("merchant").select("*").execute()
    merchants = {
        merchant["merchant_id"]: merchant
        for merchant in merchant_response.data or []
    }

    high_risk_transactions = []

    for transaction in transactions:
        transaction_id = transaction.get("transaction_id")
        transaction_status = (transaction.get("transaction_status") or "").lower()
        amount = float(transaction.get("transaction_amount") or 0)
        active_alert = active_alerts_by_transaction_id.get(transaction_id)

        high_risk_reasons = []

        if transaction_status in HIGH_RISK_TRANSACTION_STATUSES:
            high_risk_reasons.append("Transaction already flagged")

        if active_alert:
            high_risk_reasons.append(active_alert.get("alert_reason") or "Active fraud alert")

        if amount >= HIGH_RISK_AMOUNT_THRESHOLD:
            high_risk_reasons.append("High amount")

        if not high_risk_reasons:
            continue

        transaction["merchant"] = merchants.get(transaction.get("merchant_id"), {})
        transaction["risk_reason"] = ", ".join(dict.fromkeys(high_risk_reasons))
        transaction["alert_status"] = active_alert.get("alert_status") if active_alert else "Needs review"
        high_risk_transactions.append(transaction)

    return sorted(
        high_risk_transactions,
        key=lambda item: float(item.get("transaction_amount") or 0),
        reverse=True
    )


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

    if request.method == "GET" and "user_email" in session:
        session.clear()

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
                session["user_role"] = get_role_for_employee(user["employee_id"])
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

@app.route("/transactions")
def view_transactions():
    if not require_login():
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip().lower()
    flagged_only = request.args.get("flagged_only", "") == "1"

    table_name, rows, error = get_transactions_data()
    print(rows[0])
    transactions = []

    if not error:
        for row in rows:
            transaction_id = str(row.get("transaction_id", ""))
            card_id = str(row.get("card_id", ""))
            merchant_id = str(row.get("merchant_id", ""))
            device_id = str(row.get("device_id", ""))
            amount = str(row.get("transaction_amount", ""))
            timestamp = row.get("transaction_date", "")
            location = row.get("transaction_location", "")
            status = row.get("transaction_status", "")

            haystack = " ".join([
                transaction_id,
                card_id,
                merchant_id,
                device_id,
                amount,
                timestamp,
                location,
                status
            ]).lower()

            if search and search not in haystack:
                continue

            transactions.append({
                "transaction_id": transaction_id,
                "card_id": card_id,
                "merchant_id": merchant_id,
                "device_id": device_id,
                "amount": amount,
                "timestamp": timestamp,
                "location": location,
                "status": status
            })

    return render_template(
        "transactions.html",
        transactions=transactions,
        search=search,
        flagged_only=flagged_only,
        error=error,
        table_name=table_name
    )


@app.route("/suspicious-transactions")
def suspicious_transactions():
    if "user_email" not in session:
        return redirect(url_for("login"))

    transactions = get_high_risk_transactions()

    return render_template("suspicious_transactions.html", transactions=transactions, threshold=HIGH_RISK_AMOUNT_THRESHOLD)


@app.route("/suspicious-transactions/<int:transaction_id>/clear", methods=["POST"])
def clear_suspicious_transaction(transaction_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    supabase.table("fraud_alert").update({"alert_status": "resolved"}).eq("transaction_id", transaction_id).execute()
    supabase.table("transaction").update({"transaction_status": "cleared"}).eq("transaction_id", transaction_id).execute()

    return redirect(url_for("suspicious_transactions"))


@app.route("/suspicious-transactions/<int:transaction_id>/delete", methods=["POST"])
def delete_suspicious_transaction(transaction_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    supabase.table("fraud_alert").delete().eq("transaction_id", transaction_id).execute()
    supabase.table("fraud_report").delete().eq("transaction_id", transaction_id).execute()
    supabase.table("transaction").delete().eq("transaction_id", transaction_id).execute()

    return redirect(url_for("suspicious_transactions"))


@app.route("/admin")
def admin():
    if "user_email" not in session:
        return redirect(url_for("login"))
    if not require_admin():
        return "Access denied.", 403

    users = supabase.table("app_user").select("*").execute().data or []
    employees = supabase.table("employees").select("*").execute().data or []
    message = request.args.get("message", "")
    return render_template("admin.html", users=users, employees=employees, message=message)


@app.route("/admin/users/<path:user_email>/verify", methods=["POST"])
def admin_verify_user(user_email):
    if not require_admin():
        return "Access denied.", 403

    verified = request.form.get("verified") == "1"
    supabase.table("app_user").update({"employee_id_verified": verified}).eq("email", user_email).execute()
    return redirect(url_for("admin"))


@app.route("/admin/users/<path:user_email>/toggle-active", methods=["POST"])
def admin_toggle_active(user_email):
    if not require_admin():
        return "Access denied.", 403

    user = supabase.table("app_user").select("is_active").eq("email", user_email).execute().data
    if user:
        new_status = not user[0].get("is_active", True)
        supabase.table("app_user").update({"is_active": new_status}).eq("email", user_email).execute()
    return redirect(url_for("admin"))


@app.route("/admin/users/<path:user_email>/delete", methods=["POST"])
def admin_delete_user(user_email):
    if not require_admin():
        return "Access denied.", 403

    if user_email == session.get("user_email"):
        return redirect(url_for("admin", message="You cannot delete your own account."))

    supabase.table("app_user").delete().eq("email", user_email).execute()
    return redirect(url_for("admin", message=f"Deleted user {user_email}."))


@app.route("/admin/users/add", methods=["POST"])
def admin_create_user():
    if not require_admin():
        return "Access denied.", 403

    employee_id = request.form.get("employee_id", "").strip()
    first_name = request.form.get("firstname", "").strip()
    last_name = request.form.get("lastname", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not all([employee_id, first_name, last_name, email, password]):
        return redirect(url_for("admin", message="All fields are required to create a user."))

    employee_check = supabase.table("employees").select("employee_id").eq("employee_id", employee_id).execute()
    if not employee_check.data:
        return redirect(url_for("admin", message=f"Employee ID {employee_id} not found."))

    existing = supabase.table("app_user").select("email").eq("email", email).execute()
    if existing.data:
        return redirect(url_for("admin", message=f"User {email} already exists."))

    supabase.table("app_user").insert({
        "employee_id": employee_id,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "role": "analyst",
        "employee_id_verified": True,
        "is_active": True,
    }).execute()
    return redirect(url_for("admin", message=f"Created user {email}."))


@app.route("/admin/employees/add", methods=["POST"])
def admin_create_employee():
    if not require_admin():
        return "Access denied.", 403

    employee_id = request.form.get("employee_id", "").strip()
    first_name = request.form.get("firstname", "").strip()
    last_name = request.form.get("lastname", "").strip()
    department = request.form.get("department", "").strip()

    if not all([employee_id, first_name, last_name, department]):
        return redirect(url_for("admin", message="All fields are required to create an employee."))

    existing = supabase.table("employees").select("employee_id").eq("employee_id", employee_id).execute()
    if existing.data:
        return redirect(url_for("admin", message=f"Employee {employee_id} already exists."))

    supabase.table("employees").insert({
        "employee_id": employee_id,
        "firstname": first_name,
        "lastname": last_name,
        "department": department,
    }).execute()
    return redirect(url_for("admin", message=f"Created employee {employee_id}."))


@app.route("/admin/employees/<employee_id>/delete", methods=["POST"])
def admin_delete_employee(employee_id):
    if not require_admin():
        return "Access denied.", 403

    if employee_id == session.get("employee_id"):
        return redirect(url_for("admin", message="You cannot delete your own employee record."))

    supabase.table("app_user").delete().eq("employee_id", employee_id).execute()
    supabase.table("employees").delete().eq("employee_id", employee_id).execute()
    return redirect(url_for("admin", message=f"Deleted employee {employee_id}."))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
