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
def require_login():
    return "user_email" in session


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
            <li><a href="{{ url_for('suspicious_transactions') }}">Suspicious Transactions</a></li>
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

    return render_template_string("""
    <html>
    <head>
        <title>Suspicious Transactions</title>
        <style>
            body {
                background: #f4f7fb;
                color: #1f2937;
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 32px;
            }

            .page-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
            }

            .back-link {
                color: #2563eb;
                text-decoration: none;
            }

            .summary-card {
                background: #fff;
                border-left: 5px solid #dc2626;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
                margin-bottom: 24px;
                padding: 20px;
            }

            .summary-card h2 {
                color: #dc2626;
                margin: 0 0 8px;
            }

            table {
                background: #fff;
                border-collapse: collapse;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
                overflow: hidden;
                width: 100%;
            }

            th, td {
                border-bottom: 1px solid #e5e7eb;
                padding: 14px 16px;
                text-align: left;
            }

            th {
                background: #111827;
                color: #fff;
                font-size: 13px;
                letter-spacing: 0.04em;
                text-transform: uppercase;
            }

            tr:last-child td {
                border-bottom: none;
            }

            .risk-badge {
                background: #fee2e2;
                border: 1px solid #fecaca;
                border-radius: 999px;
                color: #991b1b;
                display: inline-block;
                font-weight: bold;
                padding: 6px 10px;
            }

            .empty-state {
                background: #fff;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
                padding: 32px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="page-header">
            <div>
                <h1>Suspicious Transactions</h1>
                <p>Showing only high risk transactions that need analyst review.</p>
            </div>
            <a class="back-link" href="{{ url_for('dashboard') }}">Back to Dashboard</a>
        </div>

        <div class="summary-card">
            <h2>{{ transactions|length }} High Risk Flag{{ '' if transactions|length == 1 else 's' }}</h2>
            <p>High risk includes flagged transactions, active fraud alerts, and transactions of ${{ threshold }} or more.</p>
        </div>

        {% if transactions %}
        <table>
            <tr>
                <th>Transaction ID</th>
                <th>Merchant</th>
                <th>Amount</th>
                <th>Location</th>
                <th>Status</th>
                <th>Alert Status</th>
                <th>Risk Reason</th>
            </tr>
            {% for transaction in transactions %}
            <tr>
                <td>#{{ transaction.transaction_id }}</td>
                <td>{{ transaction.merchant.merchant_name or 'Unknown merchant' }}</td>
                <td>${{ "%.2f"|format(transaction.transaction_amount|float) }}</td>
                <td>{{ transaction.transaction_location }}</td>
                <td>{{ transaction.transaction_status }}</td>
                <td>{{ transaction.alert_status }}</td>
                <td><span class="risk-badge">{{ transaction.risk_reason }}</span></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <div class="empty-state">
            <h2>No high risk transactions found</h2>
            <p>Only high risk items are shown here, so lower risk activity is hidden from this page.</p>
        </div>
        {% endif %}
    </body>
    </html>
    """, transactions=transactions, threshold=HIGH_RISK_AMOUNT_THRESHOLD)
    
@app.route("/")
def index():
    session.clear()
    return redirect(url_for("login"))

@app.route("/logout-beacon", methods=["POST"])
def logout_beacon():
    session.clear()
    return "", 204

@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("login"))
    response.delete_cookie(app.config["SESSION_COOKIE_NAME"])
    return response

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


if __name__ == "__main__":
    app.run(debug=True, port=5000)
