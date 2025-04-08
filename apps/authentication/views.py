import datetime
import json
from typing import Collection
import bcrypt
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import *
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
import pymongo
from pymongo import MongoClient
from bson import ObjectId
from django.contrib.auth import logout
from .forms import LoginForm, SignUpForm
from dotenv import load_dotenv
from datetime import datetime 
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
import os
import imaplib
import email
from email.header import decode_header
import requests
import uuid

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
        user = user_collection.find_one({"username": username})

        if user:
            hashed_password = user["password"].encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                request.session["user_id"] = str(user["_id"]) 
                print(f"User ID: {request.session['user_id']}")
                request.session["username"] = user["username"]
                print(f"Username: {request.session['username']}")
                return redirect("helpdesk_portal") 
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
            userRoles = request.POST.get("userRoles")  # Get the roles from the form
            department = request.POST.get("department")
            password = request.POST.get("password")  

            # Validate data
            if not all([userID, userName, email, mobileNo, userRoles, department, password]):
                return JsonResponse({"success": False, "message": "All fields are required."}, status=400)

            # Check if the userName or email already exists in the database
            existing_user = coll_user.find_one({"$or": [{"userName": userName}, {"email": email}]})
            if existing_user:
                if existing_user.get("userName") == userName:
                    return JsonResponse({"success": False, "message": "User Name is already taken. Please choose a different user name."}, status=400)
                if existing_user.get("email") == email:
                    return JsonResponse({"success": False, "message": "Email is already in use. Please choose a different email."}, status=400)

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            # Add 'created_at' and 'created_time'
            current_date = datetime.now().strftime('%Y-%m-%d')  # Current date in YYYY-MM-DD format
            current_time = datetime.now().strftime('%H:%M:%S')  # Current time in HH:MM:SS format

            user_data = {
                "userID": userID,
                "userName": userName,
                "email": email,
                "mobileNo": mobileNo,
                "userRole": userRoles,  # Store multiple roles as a list
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

# Function to Dispaly user List
def user_list():
    """
    Fetch the list of users from the 'coll_add_user' collection in the 'CRM_Tickit_Management_System' database.
    """
    client = MongoClient("mongodb://localhost:27017/")
    db = client["CRM_Tickit_Management_System"]
    coll_user = db["coll_add_user"]

    users_cursor = coll_user.find()

    user_list = []
    for user in users_cursor:
        user_created_at_str = user.get('created_at')

        try:
            user_created_at = datetime.strptime(user_created_at_str, '%Y-%m-%d').strftime('%d %b %Y')
        except (ValueError, TypeError):
            user_created_at = None  

        user_data = {
            '_id': str(user.get('_id')),  
            'userID': user.get('userID'),
            'userName': user.get('userName'),
            'email': user.get('email'),
            'mobileNo': user.get('mobileNo'),
            'userRole': user.get('userRole'),
            'department': user.get('department'),
            'created_at': user_created_at
        }
        user_list.append(user_data)
    
    return user_list

def view_users(request):
    ListUser = user_list()

    formatted_users = []
    for user in ListUser:
        new_user = {
            key: (str(value) if isinstance(value, ObjectId) else value)  
            for key, value in user.items()
        }
         # Add user_id (the _id from MongoDB) as a separate key
        new_user['user_id'] = new_user.get('_id')
        
        formatted_users.append(new_user)
        print("List of Formatted user",formatted_users)

    page = request.GET.get('page', 1)  
    per_page = 10  
    paginator = Paginator(formatted_users, per_page)

    try:
        users = paginator.page(page)
    except PageNotAnInteger:
        users = paginator.page(1)
    except EmptyPage:
        users = paginator.page(paginator.num_pages)

    return render(request, 'home/view-user.html', {'ListUser': users})

client = MongoClient('mongodb://localhost:27017')  
db = client['CRM_Tickit_Management_System']  
users_collection = db['coll_add_user']  

def edit_user(request, id):

    try:
        object_id = ObjectId(id)
    except Exception as e:
        return render(request, 'error.html', {'error': f'Invalid ObjectId format: {str(e)}'})

    # Query the MongoDB collection directly to find the user by _id
    user = users_collection.find_one({'_id': object_id})

    if user is None:
        return render(request, 'error.html', {'error': 'User not found'})

    # Return the user details to the edit page
    return render(request, 'home/edit-user.html', {'user': user})

def add_user_role(request):
    if request.method == "POST":
        try:
    
            client = MongoClient("mongodb://localhost:27017/")
            db = client["CRM_Tickit_Management_System"]
            role_collection = db["user_roles"]

            role_id = request.POST.get('userID')
            department = request.POST.get('department').title() 
            user_roles = request.POST.getlist('userRoles')  

            if role_id and department and user_roles:
                # Ensure user_roles is an array
                user_roles = [role.strip() for role in user_roles if role.strip()]  # Clean and filter any empty values

                # Check if the department already exists in the database
                existing_role = role_collection.find_one({"department": department})
                if existing_role:
                    client.close()
                    return JsonResponse({"message": "Error: User Role already exists!"}, status=400)

                # Get the current date and time
                current_datetime = datetime.utcnow()
                date_str = current_datetime.strftime("%d-%m-%Y")  # Date in DD-MM-YYYY format
                time_str = current_datetime.strftime("%H:%M:%S")  # Time in HH:MM:SS format

                role_data = {
                    "role_id": role_id,
                    "department": department,
                    "user_roles": user_roles,  # Store roles as an array
                    "role_creation_date": date_str,
                    "role_creation_time": time_str,
                    "role_created_at": current_datetime
                }

                role_collection.insert_one(role_data)
                client.close()

                return JsonResponse({"message": "User Role Added Successfully!"}, status=200)

            else:
                return JsonResponse({"message": "All fields are required."}, status=400)

        except Exception as e:
            return JsonResponse({"message": f"Error saving to database: {str(e)}"}, status=500)

    return render(request, 'home/add-user-role.html')


# Dashboard View Function
def add_user_view(request):
    return render(request, 'home/add-user.html')

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


# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["CRM_Tickit_Management_System"]
ticket_collection = db["email_generated_tickets"]

# Nylas API Details
NYLAS_API_KEY = "nyk_v0_DRFB1STRuvQhnfI5ifdBEqDOUAdbqBM2s0efwKVzViso904d8kJQcVJZiTyzoogu"
GRANT_ID = "fb12bcab-f5ac-4902-82e6-7aad79e6046f"
NYLAS_API_BASE = "https://api.us.nylas.com"

def fetch_support_emails_via_nylas():
    print("=" * 60)
    print("Starting Nylas email fetch process...")

    try:
        url = f"{NYLAS_API_BASE}/v3/grants/{GRANT_ID}/messages"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {NYLAS_API_KEY}",
            "Content-Type": "application/json",
        }

        params = {
            "limit": 20,
            "unread": True
        }

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        emails = response.json().get("data", [])

        print(f"Fetched {len(emails)} unread emails.")

        for i, email_obj in enumerate(emails, start=1):
            print(f"\n--- Processing Email {i} ---")

            message_id = email_obj.get("id")

            if ticket_collection.find_one({"message_id": message_id}):
                print(f"Skipping duplicate email with message_id: {message_id}")
                continue  # Skip duplicate email

            subject = email_obj.get("subject", "No Subject")
            from_email = email_obj.get("from", [{}])[0].get("email", "unknown@unknown.com")
            body = email_obj.get("snippet", "")

            ticket_id = f"T{uuid.uuid4().hex[:10].upper()}"

            now = datetime.now()
            ticket_creation_date = now.strftime("%d-%m-%Y")
            ticket_creation_time = now.strftime("%H:%M:%S")
            received_date = now.isoformat()

            ticket_data = {
                "ticket_id": ticket_id,
                "subject": subject,
                "description": body,
                "received_date": received_date,
                "ticket_creation_date": ticket_creation_date,
                "ticket_creation_time": ticket_creation_time,
                "department": "Support",
                "status": "Open",
                "email": from_email,
                "message_id": message_id,  # Storing message_id for future duplicate check
            }

            print("Inserting ticket into MongoDB...")
            ticket_collection.insert_one(ticket_data)
            print(f"Ticket Inserted with Ticket ID: {ticket_id}")

        print("\nFinished processing all Nylas emails.")
        print("=" * 60)

    except requests.exceptions.HTTPError as http_err:
        print("HTTP error occurred:", http_err)
    except Exception as e:
        print("General error occurred while fetching emails via Nylas:", str(e))

# Execute the function
fetch_support_emails_via_nylas()


""" API End Point to trigger email Fetching Function """
@csrf_exempt
def fetch_tickets_view(request):
    if request.method == "POST":
        fetch_support_emails_via_nylas()
        return JsonResponse({"message": "Fetched latest tickets from email inbox"}, status=200)
    return JsonResponse({"error": "Invalid request"}, status=400)

"""
Function to fetch tickets from MongoDB and display them in a paginated view.
This function connects to the MongoDB database, retrieves the tickets, and uses Django's 
Paginator to paginate the results.
"""
def transactions_view(request):
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["CRM_Tickit_Management_System"]
    ticket_collection = db["email_generated_tickets"]
    
    # Fetch all tickets from MongoDB
    tickets = ticket_collection.find()
    
    # Convert MongoDB cursor to a list
    ticket_list = list(tickets)
    
    # Set the number of tickets per page
    tickets_per_page = 10
    
    # Create a paginator instance
    paginator = Paginator(ticket_list, tickets_per_page)
    
    # Get the current page number from the request, default to 1 if not present
    page_number = request.GET.get('page', 1)
    
    # Get the corresponding page
    page_obj = paginator.get_page(page_number)
    
    # Render the page with the paginated data
    return render(request, 'home/transactions.html', {'page_obj': page_obj})
