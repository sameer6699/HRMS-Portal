import datetime
import json
from typing import Collection
import bcrypt
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import *
from django.contrib.auth.decorators import login_required
import pymongo
from pymongo import MongoClient
from django.contrib.auth import logout
from .forms import LoginForm, SignUpForm
from dotenv import load_dotenv
from datetime import datetime
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import os

# user Name :- Sameer_Jadhav
# Password :- sameer@6699

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB credentials from .env file
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME")
MONGODB_USER = os.getenv("MONGODB_USER")
MONGODB_PASS = os.getenv("MONGODB_PASS")

# MongoDB Connection using the retrieved credentials
client = pymongo.MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
user_collection = db['coll_register_user']

# Landing Page Redirection
def landing_page(request):
    # Checking the Connection is established Properly or not
    # This is just a print statement to check the connection
    print(f"MongoDB URI: {MONGO_URI}")
    print(f"MongoDB DB Name: {MONGO_DB_NAME}")
    print(f"MongoDB User: {MONGODB_USER}")
    print(f"MongoDB Password: {MONGODB_PASS}")
    return render(request, 'home/index.html')

def login_view(request):
    """
    Custom login function that verifies user credentials from MongoDB.
    """
    msg = None

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Check if the username exists in the database
        user = user_collection.find_one({"username": username})

        if user:
            # Retrieve hashed password from the database
            hashed_password = user["password"].encode('utf-8')

            # Verify entered password with stored hashed password
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                # Authentication successful - Redirect to home page
                request.session["user_id"] = str(user["_id"])  # Store user session
                print(f"User ID: {request.session['user_id']}")
                request.session["username"] = user["username"]
                print(f"Username: {request.session['username']}")
                return redirect("helpdesk_portal")  # Redirect to dashboard or home page
            else:
                msg = "Invalid credentials. Please try again."
        else:
            msg = "User does not exist. Please register first."

    return render(request, "accounts/login.html", {"msg": msg})


def logout_view(request):
    print("Logout function called")
    """
    Custom logout function to clear session data.
    """
    if "user_id" in request.session:
        request.session.flush()  # Clears all session data

    return redirect("/login/")
# Function to handle user Registration in the signIN view section
def register_user(request):
    msg = None
    success = False

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        # Custom validation for passwords matching
        if password1 != password2:
            msg = "Passwords do not match!"
        else:
            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())

            # Get current registration date
            registration_date = datetime.utcnow()

            # Save user data in MongoDB
            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password.decode('utf-8'),  # Store hashed password as string
                "registration_date": registration_date
            }

            # Insert data into MongoDB
            user_collection.insert_one(user_data)

            msg = "User registered successfully!"
            success = True
            return redirect("/login/")

    return render(request, "accounts/register.html", {"msg": msg, "success": success})

# Here in this rote user is redirected to the dashboard page after login.
def help_desk_portal(request):
    if "user_id" not in request.session:
        return redirect("/login/") 
    return render(request, 'home/dashboard.html')  

def dashboard_view(request):
    return render(request, 'home/dashboard.html')

# Function to add user data into MongoDB
def add_user_data(request):
    if request.method == "POST":
        try:
            print("Request received!") 
            client = MongoClient("mongodb://localhost:27017/")  
            db = client["CRM_Tickit_Management_System"]  
            coll_user = db["coll_add_user"]

            if not request.POST:
                return JsonResponse({"success": False, "message": "No data received!"}, status=400)

            # Extract user data
            userID = request.POST.get("userID")
            userName = request.POST.get("userName")
            email = request.POST.get("email")
            mobileNo = request.POST.get("mobileNo")
            userRole = request.POST.get("userRole")
            department = request.POST.get("department")
            password = request.POST.get("password")  

            # Validate data
            if not all([userID, userName, email, mobileNo, userRole, department, password]):
                return JsonResponse({"success": False, "message": "All fields are required."}, status=400)

            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            user_data = {
                "userID": userID,
                "userName": userName,
                "email": email,
                "mobileNo": mobileNo,
                "userRole": userRole,
                "department": department,
                "password": hashed_password.decode("utf-8"), 
            }

            insert_result = coll_user.insert_one(user_data)

            if insert_result.inserted_id:
                return JsonResponse({"success": True, "message": "User added successfully!"})
            else:
                return JsonResponse({"success": False, "message": "Failed to add user."}, status=500)

        except Exception as e:
            print("Error:", e)  # Debugging
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Invalid request method."}, status=405)


# Dashboard View Function
def add_user_view(request):
    return render(request, 'home/add-user.html')


def transactions_view(request):
    return render(request, 'home/transactions.html')

def settings_view(request):
    return render(request, 'home/settings.html')

def bootstrap_tables_view(request):
    return render(request, 'home/tables-bootstrap-tables.html')

def forgot_password_view(request):
    return render(request, 'home/page-forgot-password.html')

def reset_password_view(request):
    return render(request, 'home/page-reset-password.html')

def page_404_view(request):
    return render(request, 'home/page-404.html')

def page_500_view(request):
    return render(request, 'home/page-500.html')

def buttons_view(request):
    return render(request, 'home/components-buttons.html')

def notifications_view(request):
    return render(request, 'home/components-notifications.html')

def forms_view(request):
    return render(request, 'home/components-forms.html')

def modals_view(request):
    return render(request, 'home/components-modals.html')

def typography_view(request):
    return render(request, 'home/components-typography.html')