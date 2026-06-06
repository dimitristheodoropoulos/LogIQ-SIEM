from pymongo import MongoClient
import sys

def create_admin():
    try:
        # Συνδεόμαστε στη Mongo (που κάνει port forward στο 27017 του localhost)
        client = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=5000)
        db = client["logiq"]
        users_collection = db["users"]

        # Στοιχεία Admin
        admin_user = {
            "username": "admin",
            "password": "admin" # Σημείωση: Σε production θα έπρεπε να είναι hashed!
        }

        if users_collection.find_one({"username": "admin"}):
            print("⚠️ Ο χρήστης 'admin' υπάρχει ήδη.")
        else:
            users_collection.insert_one(admin_user)
            print("✅ Ο χρήστης 'admin' δημιουργήθηκε με επιτυχία!")
            
    except Exception as e:
        print(f"❌ Σφάλμα σύνδεσης στη MongoDB: {e}")

if __name__ == "__main__":
    create_admin()