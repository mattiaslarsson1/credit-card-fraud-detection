import os
from flask import Flask
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

url = os.environ["SUPABASE_URL"]
key = os.environ["SUPABASE_KEY"]

supabase: Client = create_client(url, key)


@app.route("/")
def home():
    response = supabase.table("bank").select("*").execute()
    rows = response.data or []

    html = """
    <html>
    <head>
        <title>Bank Table</title>
    </head>
    <body>
        <h1>Bank Table</h1>
        <p>This page is coming from Flask + Supabase.</p>
        <table border="1" cellpadding="8">
            <tr>
                <th>bank_id</th>
                <th>bank_name</th>
                <th>location</th>
                <th>phone</th>
                <th>number_of_users</th>
            </tr>
    """

    for row in rows:
        html += f"""
            <tr>
                <td>{row.get('bank_id', '')}</td>
                <td>{row.get('bank_name', '')}</td>
                <td>{row.get('location', '')}</td>
                <td>{row.get('phone', '')}</td>
                <td>{row.get('number_of_users', '')}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(debug=True, port=5000)

