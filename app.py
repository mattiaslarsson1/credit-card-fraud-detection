import os
from datetime import datetime, timezone
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
    latest_alert_by_transaction_id = {}

    for alert in alerts:
        alert_status = (alert.get("alert_status") or "").lower()
        tid = alert.get("transaction_id")
        # Track the most recent alert for display regardless of status
        existing = latest_alert_by_transaction_id.get(tid)
        if not existing or (alert.get("alert_id", 0) > existing.get("alert_id", 0)):
            latest_alert_by_transaction_id[tid] = alert
        if alert_status in HIGH_RISK_ALERT_STATUSES:
            active_alerts_by_transaction_id[tid] = alert

    merchant_response = supabase.table("merchant").select("*").execute()
    merchants = {
        merchant["merchant_id"]: merchant
        for merchant in merchant_response.data or []
    }

    REVIEWED_ALERT_STATUSES = {"cleared"}

    high_risk_transactions = []

    for transaction in transactions:
        transaction_id = transaction.get("transaction_id")
        transaction_status = (transaction.get("transaction_status") or "").lower()
        amount = float(transaction.get("transaction_amount") or 0)
        active_alert = active_alerts_by_transaction_id.get(transaction_id)
        latest_alert = latest_alert_by_transaction_id.get(transaction_id)

        # Skip if already reviewed by an analyst
        if latest_alert and (latest_alert.get("alert_status") or "").lower() in REVIEWED_ALERT_STATUSES:
            continue

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
        transaction["alert_status"] = latest_alert.get("alert_status") if latest_alert else "No alert"
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
    message = request.args.get("message", "")

    table_name, rows, error = get_transactions_data()

    # Fetch latest alert status per transaction
    alert_rows = supabase.table("fraud_alert").select("transaction_id, alert_status, alert_id").execute().data or []
    latest_alert = {}
    for a in alert_rows:
        tid = a["transaction_id"]
        if tid not in latest_alert or a["alert_id"] > latest_alert[tid]["alert_id"]:
            latest_alert[tid] = a

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
            alert = latest_alert.get(row.get("transaction_id"))
            alert_status = alert["alert_status"] if alert else ""

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
                "status": status,
                "alert_status": alert_status
            })

    return render_template(
        "transactions.html",
        transactions=transactions,
        search=search,
        flagged_only=flagged_only,
        error=error,
        table_name=table_name,
        message=message
    )


@app.route("/transactions/add", methods=["POST"])
def add_transaction():
    if not require_login():
        return redirect(url_for("login"))

    card_id = request.form.get("card_id", "").strip()
    merchant_id = request.form.get("merchant_id", "").strip()
    device_id = request.form.get("device_id", "").strip()
    amount = request.form.get("amount", "").strip()
    date = request.form.get("date", "").strip()
    location = request.form.get("location", "").strip()
    status = request.form.get("status", "pending").strip()

    if not all([card_id, merchant_id, amount, date, location]):
        return redirect(url_for("view_transactions", message="Card ID, Merchant ID, Amount, Date, and Location are required."))

    try:
        supabase.table("transaction").insert({
            "card_id": int(card_id),
            "merchant_id": int(merchant_id),
            "device_id": int(device_id) if device_id else None,
            "transaction_amount": float(amount),
            "transaction_date": date,
            "transaction_location": location,
            "transaction_status": status
        }).execute()
    except Exception as e:
        return redirect(url_for("view_transactions", message=f"Error inserting transaction: {e}"))

    return redirect(url_for("view_transactions", message="Transaction added successfully."))


@app.route("/transactions/<int:transaction_id>/flag", methods=["POST"])
def flag_transaction(transaction_id):
    if not require_login():
        return redirect(url_for("login"))

    # Only create an alert if one doesn't already exist
    existing = supabase.table("fraud_alert").select("alert_id").eq("transaction_id", transaction_id).execute().data
    if not existing:
        supabase.table("fraud_alert").insert({
            "transaction_id": transaction_id,
            "alert_reason": "Manually flagged by analyst",
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "alert_status": "open"
        }).execute()
    else:
        supabase.table("fraud_alert").update({"alert_status": "open"}).eq("transaction_id", transaction_id).execute()

    return redirect(url_for("view_transactions"))


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

    existing = supabase.table("fraud_alert").select("alert_id").eq("transaction_id", transaction_id).execute().data
    if existing:
        supabase.table("fraud_alert").update({"alert_status": "cleared"}).eq("transaction_id", transaction_id).execute()
    else:
        supabase.table("fraud_alert").insert({
            "transaction_id": transaction_id,
            "alert_reason": "Manually reviewed",
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "alert_status": "cleared"
        }).execute()

    return redirect(url_for("suspicious_transactions"))


@app.route("/suspicious-transactions/<int:transaction_id>/flag", methods=["POST"])
def flag_as_fraud(transaction_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    # Resolve customer_id via transaction -> credit_card -> account -> customer
    customer_id = None
    txn_data = supabase.table("transaction").select("card_id").eq("transaction_id", transaction_id).execute().data
    if txn_data:
        card_id = txn_data[0].get("card_id")
        if card_id:
            card_data = supabase.table("credit_card").select("account_id").eq("card_id", card_id).execute().data
            if card_data:
                account_id = card_data[0].get("account_id")
                if account_id:
                    account_data = supabase.table("account").select("customer_id").eq("account_id", account_id).execute().data
                    if account_data:
                        customer_id = account_data[0].get("customer_id")

    # Only create a report if one doesn't already exist for this transaction
    existing_report = supabase.table("fraud_report").select("report_id").eq("transaction_id", transaction_id).execute().data
    if not existing_report:
        supabase.table("fraud_report").insert({
            "customer_id": customer_id,
            "transaction_id": transaction_id,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "resolution_status": "open"
        }).execute()

    # Mark alert status as flagged (create alert if none exists)
    existing_alert = supabase.table("fraud_alert").select("alert_id").eq("transaction_id", transaction_id).execute().data
    if existing_alert:
        supabase.table("fraud_alert").update({"alert_status": "flagged"}).eq("transaction_id", transaction_id).execute()
    else:
        supabase.table("fraud_alert").insert({
            "transaction_id": transaction_id,
            "alert_reason": "Manually flagged as fraud",
            "alert_date": datetime.now(timezone.utc).isoformat(),
            "alert_status": "flagged"
        }).execute()

    return redirect(url_for("suspicious_transactions"))


@app.route("/fraud-reports")
def fraud_reports():
    if "user_email" not in session:
        return redirect(url_for("login"))

    reports = supabase.table("fraud_report").select("*").order("report_date", desc=True).execute().data or []

    transaction_ids = [r["transaction_id"] for r in reports if r.get("transaction_id")]
    customer_ids = [r["customer_id"] for r in reports if r.get("customer_id")]

    transactions = {}
    if transaction_ids:
        txn_rows = supabase.table("transaction").select("*").in_("transaction_id", transaction_ids).execute().data or []
        transactions = {t["transaction_id"]: t for t in txn_rows}

    customers = {}
    if customer_ids:
        cust_rows = supabase.table("customer").select("*").in_("customer_id", customer_ids).execute().data or []
        customers = {c["customer_id"]: c for c in cust_rows}

    for report in reports:
        report["transaction"] = transactions.get(report.get("transaction_id"), {})
        report["customer"] = customers.get(report.get("customer_id"), {})

    return render_template("fraud_reports.html", reports=reports)


@app.route("/fraud-reports/<int:report_id>/resolve", methods=["POST"])
def resolve_fraud_report(report_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    supabase.table("fraud_report").update({"resolution_status": "resolved"}).eq("report_id", report_id).execute()
    return redirect(url_for("fraud_reports"))


@app.route("/fraud-reports/<int:report_id>/delete", methods=["POST"])
def delete_fraud_report(report_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    supabase.table("fraud_report").delete().eq("report_id", report_id).execute()
    return redirect(url_for("fraud_reports"))


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
