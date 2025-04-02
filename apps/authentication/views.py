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
from bson import ObjectId
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

# Function to handle user login in section
def user_login(request):
    return render(request, 'accounts/user_login.html')

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

            # Check if the userName or email already exist in the database
            existing_user = coll_user.find_one({"$or": [{"userName": userName}, {"email": email}]})
            
            if existing_user:
                if existing_user.get("userName") == userName:
                    return JsonResponse({"success": False, "message": "User Name is already taken use different user name."}, status=400)
                if existing_user.get("email") == email:
                    return JsonResponse({"success": False, "message": "Email is already in use use different email."}, status=400)

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            # Add 'created_at' and 'created_time'
            current_date = datetime.now().strftime('%Y-%m-%d')  # Current date in YYYY-MM-DD format
            current_time = datetime.now().strftime('%H:%M:%S')  # Current time in HH:MM:SS format

            # User data including the new fields
            user_data = {
                "userID": userID,
                "userName": userName,
                "email": email,
                "mobileNo": mobileNo,
                "userRole": userRole,
                "department": department,
                "password": hashed_password.decode("utf-8"), 
                "created_at": current_date,  # Adding created_at
                "created_time": current_time,  # Adding created_time
            }

            # Insert data into MongoDB
            insert_result = coll_user.insert_one(user_data)

            # Check if the insertion was successful
            if insert_result.inserted_id:
                return JsonResponse({"success": True, "message": "User added successfully!"})
            else:
                return JsonResponse({"success": False, "message": "Failed to add user."}, status=500)

        except Exception as e:
            print("Error:", e)  # Debugging
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Invalid request method."}, status=405)

def user_list(request):
    """
    Fetch the list of users from the 'coll_add_user' collection in the 'CRM_Tickit_Management_System' database.
    """
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["CRM_Tickit_Management_System"]
    coll_user = db["coll_add_user"]

    # Fetch all users from the 'coll_add_user' collection
    users_cursor = coll_user.find()

    user_list = []
    for user in users_cursor:
        # Get created_at, which is stored as a string in the 'YYYY-MM-DD' format
        user_created_at_str = user.get('created_at')

        # Convert the string to a datetime object
        try:
            user_created_at = datetime.strptime(user_created_at_str, '%Y-%m-%d')  # ✅ Correct usage
            # Format the date as 'DD MMM YYYY'
            user_created_at = user_created_at.strftime('%d %b %Y')
        except (ValueError, TypeError):
            user_created_at = None  # Handle errors gracefully

        # Prepare user data
        user_data = {
            '_id': str(user.get('_id')),  # Convert ObjectId to string
            'userID': user.get('userID'),
            'userName': user.get('userName'),
            'email': user.get('email'),
            'mobileNo': user.get('mobileNo'),
            'userRole': user.get('userRole'),
            'department': user.get('department'),
            'created_at': user_created_at  # Formatted date
        }
        user_list.append(user_data)
        print("Response of the user List in list format ----------->", user_list)
        

    return user_list

def view_users(request):
    # Fetch User List
    ListUser = user_list(request)  # Pass request properly
    print("List user variable List:", ListUser)

    formatted_users = []
    for user in ListUser:
        new_user = {
            key: (str(value) if isinstance(value, ObjectId) else value)  # Convert ObjectID to String
            for key, value in user.items()
        }
        formatted_users.append(new_user)
        print("List of formatted Users --------------------------------->", formatted_users)

    return render(request, 'home/view-user.html', {'ListUser': formatted_users})

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