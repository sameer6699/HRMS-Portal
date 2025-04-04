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



client = MongoClient("mongodb://localhost:27017/")
db = client["CRM_Tickit_Management_System"]
ticket_collection = db["email_generated_tickets"]

# Outlook Mail Credentials
EMAIL_HOST = "imap-mail.outlook.com" 
EMAIL_USER = "Sameer.Jadhav@thesilvertech.com"  
EMAIL_PASS = "Sjadhav@#$123"  

def fetch_support_emails():
    """Fetch unread support emails and convert them into tickets."""
    print("Starting to fetch emails...")
    try:
        # Connect to Outlook's IMAP server
        print(f"Connecting to IMAP server: {EMAIL_HOST}")
        mail = imaplib.IMAP4_SSL(EMAIL_HOST)
        print(f"Logging in with email: {EMAIL_USER}")
        mail.login(EMAIL_USER, EMAIL_PASS)
        
        # Select the inbox
        print("Selecting the inbox...")
        mail.select("inbox")
        
        # Search for all UNSEEN emails
        print("Searching for UNSEEN emails...")
        status, messages = mail.search(None, "UNSEEN")
        print(f"Search status: {status}")
        
        if status != 'OK':
            print("No unread emails found!")
            return

        mail_ids = messages[0].split()
        print(f"Number of unread emails found: {len(mail_ids)}")

        for mail_id in mail_ids:
            print(f"Processing email ID: {mail_id}")
            _, msg_data = mail.fetch(mail_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # Decode subject
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8")
            print(f"Decoded Subject: {subject}")

            # Decode sender email
            from_email = msg.get("From")
            print(f"Sender Email: {from_email}")

            # Get email content
            if msg.is_multipart():
                print("Email is multipart, extracting text/plain part...")
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                        print("Email body (text/plain):", body[:200])
                        break
            else:
                body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                print("Email body:", body[:200])

            # Generate Ticket ID
            ticket_id = f"T{datetime.now().strftime('%Y%m%d%H%M%S')}"
            print(f"Generated Ticket ID: {ticket_id}")

            # Prepare ticket data
            ticket_data = {
                "ticket_id": ticket_id,
                "subject": subject,
                "description": body,
                "received_date": datetime.now().isoformat(),
                "department": "Support",
                "status": "Open",
                "email": from_email,
            }
            
            # Save to MongoDB
            print(f"Inserting ticket data into MongoDB: {ticket_data}")
            ticket_collection.insert_one(ticket_data)

            # Mark email as seen
            print(f"Marking email ID {mail_id} as read...")
            mail.store(mail_id, "+FLAGS", "\\Seen")

        print("Finished processing emails.")
        mail.logout()

    except Exception as e:
        print("Error fetching emails:", str(e))

# Call the function to test
fetch_support_emails()

""" API End Point to trigger email Fetching Function """
@csrf_exempt
def fetch_tickets_view(request):
    if request.method == "POST":
        fetch_support_emails()
        return JsonResponse({"message": "Fetched latest tickets from email inbox"}, status=200)
    return JsonResponse({"error": "Invalid request"}, status=400)