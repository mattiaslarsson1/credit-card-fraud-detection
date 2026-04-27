import os
import json
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from urllib.parse import urlparse, unquote

import pg8000.dbapi

from flask import Flask, request, redirect, session, url_for, render_template, render_template_string
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["SESSION_PERMANENT"] = False

DATABASE_URL = os.environ["DATABASE_URL"]
_db_url = urlparse(DATABASE_URL)
DB_CONFIG = {
    "user": unquote(_db_url.username) if _db_url.username else None,
    "password": unquote(_db_url.password) if _db_url.password else None,
    "host": _db_url.hostname,
    "port": _db_url.port or 5432,
    "database": _db_url.path.lstrip("/"),
    "ssl_context": True,
}


def open_connection():
    return pg8000.dbapi.connect(**DB_CONFIG)


@contextmanager
def get_cursor():
    conn = open_connection()
    try:
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
    finally:
        conn.close()


def db_query(sql, params=None):
    with get_cursor() as cur:
        cur.execute(sql, params or ())
        if cur.description is None:
            return None
        columns = [col[0] for col in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def db_execute(sql, params=None):
    with get_cursor() as cur:
        cur.execute(sql, params or ())


def require_login():
    return "user_email" in session


SECURITY_DEPARTMENT = "security"


def get_role_for_employee(employee_id):
    if not employee_id:
        return "analyst"
    rows = db_query(
        "SELECT department FROM employees WHERE employee_id = %s",
        (employee_id,),
    )
    if not rows:
        return "analyst"
    department = (rows[0].get("department") or "").strip().lower()
    return "admin" if department == SECURITY_DEPARTMENT else "analyst"


def require_admin():
    return "user_email" in session and session.get("user_role") == "admin"


def start_user_session(user):
    session.clear()
    session.permanent = False
    session["user_email"] = user["email"]
    session["user_name"] = f"{user['first_name']} {user['last_name']}"
    session["user_role"] = user["role"]
    session["employee_id"] = user["employee_id"]
    session["browser_session_token"] = uuid.uuid4().hex


def authenticated_response_guard():
    if "user_email" not in session:
        return ""

    token = json.dumps(session.get("browser_session_token", ""))
    logout_url = json.dumps(url_for("logout"))

    return f"""
        <script>
            (function () {{
                var key = "bankFraudSessionToken";
                var expectedToken = {token};

                function endRestoredSession() {{
                    if (window.sessionStorage.getItem(key) !== expectedToken) {{
                        window.location.replace({logout_url});
                    }}
                }}

                endRestoredSession();
                window.addEventListener("pageshow", function (event) {{
                    if (event.persisted) {{
                        endRestoredSession();
                    }}
                }});
            }})();
        </script>
    """


@app.after_request
def prevent_private_page_cache(response):
    if "user_email" in session:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        if response.content_type and response.content_type.startswith("text/html"):
            body = response.get_data(as_text=True)
            guard = authenticated_response_guard()
            if "</body>" in body:
                body = body.replace("</body>", guard + "\n</body>")
            else:
                body += guard
            response.set_data(body)
            response.headers["Content-Length"] = str(len(response.get_data()))

    return response


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
            rows = db_query(f"SELECT * FROM {table_name}")
            return table_name, rows or [], None
        except Exception as e:
            last_error = str(e)

    return None, [], last_error


HIGH_RISK_AMOUNT_THRESHOLD = 500
HIGH_RISK_ALERT_STATUSES = {"open", "investigating"}
HIGH_RISK_TRANSACTION_STATUSES = {"flagged"}


def get_high_risk_transactions():
    transactions = db_query("SELECT * FROM transaction") or []
    alerts = db_query("SELECT * FROM fraud_alert") or []

    active_alerts_by_transaction_id = {}
    latest_alert_by_transaction_id = {}

    for alert in alerts:
        alert_status = (alert.get("alert_status") or "").lower()
        tid = alert.get("transaction_id")
        existing = latest_alert_by_transaction_id.get(tid)
        if not existing or (alert.get("alert_id", 0) > existing.get("alert_id", 0)):
            latest_alert_by_transaction_id[tid] = alert
        if alert_status in HIGH_RISK_ALERT_STATUSES:
            active_alerts_by_transaction_id[tid] = alert

    merchant_rows = db_query("SELECT * FROM merchant") or []
    merchants = {m["merchant_id"]: m for m in merchant_rows}

    REVIEWED_ALERT_STATUSES = {"cleared"}

    high_risk_transactions = []

    for transaction in transactions:
        transaction_id = transaction.get("transaction_id")
        transaction_status = (transaction.get("transaction_status") or "").lower()
        amount = float(transaction.get("transaction_amount") or 0)
        active_alert = active_alerts_by_transaction_id.get(transaction_id)
        latest_alert = latest_alert_by_transaction_id.get(transaction_id)

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
    start_user_session({
        "email": "dev@test.com",
        "first_name": "Dev",
        "last_name": "User",
        "role": "admin",
        "employee_id": "EMP001"
    })
    return render_template(
        "login_success.html",
        session_token=session["browser_session_token"],
        next_url=url_for("dashboard")
    )


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
            employee_check = db_query(
                "SELECT employee_id FROM employees WHERE employee_id = %s",
                (employee_id,),
            )

            if not employee_check:
                message = "Employee ID not found. Please contact your administrator."
            else:
                existing = db_query(
                    "SELECT email FROM app_user WHERE email = %s",
                    (email,),
                )

                if existing:
                    message = "An account with that email already exists."
                else:
                    password_hash = generate_password_hash(password)
                    inserted = db_query(
                        """
                        INSERT INTO app_user
                            (employee_id, first_name, last_name, email,
                             password_hash, role, employee_id_verified, is_active)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING email
                        """,
                        (
                            employee_id, first_name, last_name, email,
                            password_hash, "analyst", False, True,
                        ),
                    )

                    if inserted:
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

        users = db_query(
            "SELECT * FROM app_user WHERE email = %s",
            (email,),
        ) or []

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
                user["role"] = get_role_for_employee(user["employee_id"])
                start_user_session(user)
                return render_template(
                    "login_success.html",
                    session_token=session["browser_session_token"],
                    next_url=url_for("dashboard")
                )

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

    customers = db_query("SELECT * FROM customer") or []
    return render_template("customers.html", customers=customers)


@app.route("/customers/add", methods=["GET", "POST"])
def add_customer():
    if "user_email" not in session:
        return redirect(url_for("login"))

    message = ""

    banks = db_query("SELECT bank_id, bank_name FROM bank") or []

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
            try:
                inserted = db_query(
                    """
                    INSERT INTO customer
                        (bank_id, first_name, last_name, email, phone, date_of_birth, address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING customer_id
                    """,
                    (
                        int(bank_id), first_name, last_name, email,
                        phone or None, date_of_birth or None, address or None,
                    ),
                )
                if inserted:
                    return redirect(url_for("view_customers"))
                message = "Error adding customer."
            except Exception as e:
                message = f"Error adding customer: {e}"

    return render_template("add_customer.html", banks=banks, message=message)


@app.route("/transactions")
def view_transactions():
    if not require_login():
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip().lower()
    flagged_only = request.args.get("flagged_only", "") == "1"
    message = request.args.get("message", "")

    table_name, rows, error = get_transactions_data()

    alert_rows = db_query(
        "SELECT transaction_id, alert_status, alert_id FROM fraud_alert"
    ) or []
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
                transaction_id, card_id, merchant_id, device_id,
                amount, str(timestamp), str(location), str(status)
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
        db_execute(
            """
            INSERT INTO transaction
                (card_id, merchant_id, device_id, transaction_amount,
                 transaction_date, transaction_location, transaction_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                int(card_id),
                int(merchant_id),
                int(device_id) if device_id else None,
                float(amount),
                date,
                location,
                status,
            ),
        )
    except Exception as e:
        return redirect(url_for("view_transactions", message=f"Error inserting transaction: {e}"))

    return redirect(url_for("view_transactions", message="Transaction added successfully."))


@app.route("/transactions/<int:transaction_id>/flag", methods=["POST"])
def flag_transaction(transaction_id):
    if not require_login():
        return redirect(url_for("login"))

    existing = db_query(
        "SELECT alert_id FROM fraud_alert WHERE transaction_id = %s",
        (transaction_id,),
    )
    if not existing:
        db_execute(
            """
            INSERT INTO fraud_alert
                (transaction_id, alert_reason, alert_date, alert_status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                transaction_id,
                "Manually flagged by analyst",
                datetime.now(timezone.utc).isoformat(),
                "open",
            ),
        )
    else:
        db_execute(
            "UPDATE fraud_alert SET alert_status = %s WHERE transaction_id = %s",
            ("open", transaction_id),
        )

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

    existing = db_query(
        "SELECT alert_id FROM fraud_alert WHERE transaction_id = %s",
        (transaction_id,),
    )
    if existing:
        db_execute(
            "UPDATE fraud_alert SET alert_status = %s WHERE transaction_id = %s",
            ("cleared", transaction_id),
        )
    else:
        db_execute(
            """
            INSERT INTO fraud_alert
                (transaction_id, alert_reason, alert_date, alert_status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                transaction_id,
                "Manually reviewed",
                datetime.now(timezone.utc).isoformat(),
                "cleared",
            ),
        )

    return redirect(url_for("suspicious_transactions"))


@app.route("/suspicious-transactions/<int:transaction_id>/flag", methods=["POST"])
def flag_as_fraud(transaction_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    customer_rows = db_query(
        """
        SELECT a.customer_id
        FROM transaction t
        JOIN credit_card cc ON cc.card_id = t.card_id
        JOIN account     a  ON a.account_id = cc.account_id
        WHERE t.transaction_id = %s
        """,
        (transaction_id,),
    )
    customer_id = customer_rows[0]["customer_id"] if customer_rows else None

    existing_report = db_query(
        "SELECT report_id FROM fraud_report WHERE transaction_id = %s",
        (transaction_id,),
    )
    if not existing_report:
        db_execute(
            """
            INSERT INTO fraud_report
                (customer_id, transaction_id, report_date, resolution_status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                customer_id,
                transaction_id,
                datetime.now(timezone.utc).isoformat(),
                "open",
            ),
        )

    existing_alert = db_query(
        "SELECT alert_id FROM fraud_alert WHERE transaction_id = %s",
        (transaction_id,),
    )
    if existing_alert:
        db_execute(
            "UPDATE fraud_alert SET alert_status = %s WHERE transaction_id = %s",
            ("flagged", transaction_id),
        )
    else:
        db_execute(
            """
            INSERT INTO fraud_alert
                (transaction_id, alert_reason, alert_date, alert_status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                transaction_id,
                "Manually flagged as fraud",
                datetime.now(timezone.utc).isoformat(),
                "flagged",
            ),
        )

    return redirect(url_for("suspicious_transactions"))


@app.route("/fraud-reports")
def fraud_reports():
    if "user_email" not in session:
        return redirect(url_for("login"))

    reports = db_query(
        "SELECT * FROM fraud_report ORDER BY report_date DESC"
    ) or []

    transaction_ids = [r["transaction_id"] for r in reports if r.get("transaction_id")]
    customer_ids = [r["customer_id"] for r in reports if r.get("customer_id")]

    transactions = {}
    if transaction_ids:
        txn_rows = db_query(
            "SELECT * FROM transaction WHERE transaction_id = ANY(%s)",
            (transaction_ids,),
        ) or []
        transactions = {t["transaction_id"]: t for t in txn_rows}

    customers = {}
    if customer_ids:
        cust_rows = db_query(
            "SELECT * FROM customer WHERE customer_id = ANY(%s)",
            (customer_ids,),
        ) or []
        customers = {c["customer_id"]: c for c in cust_rows}

    for report in reports:
        report["transaction"] = transactions.get(report.get("transaction_id"), {})
        report["customer"] = customers.get(report.get("customer_id"), {})

    return render_template("fraud_reports.html", reports=reports)


@app.route("/fraud-reports/<int:report_id>/resolve", methods=["POST"])
def resolve_fraud_report(report_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    db_execute(
        "UPDATE fraud_report SET resolution_status = %s WHERE report_id = %s",
        ("resolved", report_id),
    )
    return redirect(url_for("fraud_reports"))


@app.route("/fraud-reports/<int:report_id>/delete", methods=["POST"])
def delete_fraud_report(report_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    db_execute(
        "DELETE FROM fraud_report WHERE report_id = %s",
        (report_id,),
    )
    return redirect(url_for("fraud_reports"))


@app.route("/admin")
def admin():
    if "user_email" not in session:
        return redirect(url_for("login"))
    if not require_admin():
        return "Access denied.", 403

    users = db_query("SELECT * FROM app_user") or []
    employees = db_query("SELECT * FROM employees") or []
    message = request.args.get("message", "")
    return render_template("admin.html", users=users, employees=employees, message=message)


@app.route("/admin/users/<path:user_email>/verify", methods=["POST"])
def admin_verify_user(user_email):
    if not require_admin():
        return "Access denied.", 403

    verified = request.form.get("verified") == "1"
    db_execute(
        "UPDATE app_user SET employee_id_verified = %s WHERE email = %s",
        (verified, user_email),
    )
    return redirect(url_for("admin"))


@app.route("/admin/users/<path:user_email>/toggle-active", methods=["POST"])
def admin_toggle_active(user_email):
    if not require_admin():
        return "Access denied.", 403

    rows = db_query(
        "SELECT is_active FROM app_user WHERE email = %s",
        (user_email,),
    )
    if rows:
        new_status = not rows[0].get("is_active", True)
        db_execute(
            "UPDATE app_user SET is_active = %s WHERE email = %s",
            (new_status, user_email),
        )
    return redirect(url_for("admin"))


@app.route("/admin/users/<path:user_email>/delete", methods=["POST"])
def admin_delete_user(user_email):
    if not require_admin():
        return "Access denied.", 403

    if user_email == session.get("user_email"):
        return redirect(url_for("admin", message="You cannot delete your own account."))

    db_execute("DELETE FROM app_user WHERE email = %s", (user_email,))
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

    employee_check = db_query(
        "SELECT employee_id FROM employees WHERE employee_id = %s",
        (employee_id,),
    )
    if not employee_check:
        return redirect(url_for("admin", message=f"Employee ID {employee_id} not found."))

    existing = db_query(
        "SELECT email FROM app_user WHERE email = %s",
        (email,),
    )
    if existing:
        return redirect(url_for("admin", message=f"User {email} already exists."))

    db_execute(
        """
        INSERT INTO app_user
            (employee_id, first_name, last_name, email,
             password_hash, role, employee_id_verified, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            employee_id, first_name, last_name, email,
            generate_password_hash(password), "analyst", True, True,
        ),
    )
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

    existing = db_query(
        "SELECT employee_id FROM employees WHERE employee_id = %s",
        (employee_id,),
    )
    if existing:
        return redirect(url_for("admin", message=f"Employee {employee_id} already exists."))

    db_execute(
        """
        INSERT INTO employees (employee_id, firstname, lastname, department)
        VALUES (%s, %s, %s, %s)
        """,
        (employee_id, first_name, last_name, department),
    )
    return redirect(url_for("admin", message=f"Created employee {employee_id}."))


@app.route("/admin/employees/<employee_id>/delete", methods=["POST"])
def admin_delete_employee(employee_id):
    if not require_admin():
        return "Access denied.", 403

    if employee_id == session.get("employee_id"):
        return redirect(url_for("admin", message="You cannot delete your own employee record."))

    db_execute("DELETE FROM app_user WHERE employee_id = %s", (employee_id,))
    db_execute("DELETE FROM employees WHERE employee_id = %s", (employee_id,))
    return redirect(url_for("admin", message=f"Deleted employee {employee_id}."))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
