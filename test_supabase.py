import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url = os.environ["SUPABASE_URL"]
key = os.environ["SUPABASE_KEY"]

supabase: Client = create_client(url, key)

response = supabase.table("bank").select("*").execute()

print("Connected to Supabase.")
print(response.data)
