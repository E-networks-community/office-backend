from io import StringIO, BytesIO
import pandas as pd
import zipfile
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from functools import wraps
import json
from datetime import datetime
import uuid
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, session, send_file
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from models import SuccessfulPayment
from models import Role, db, User, Admin, Form, SuccessfulReferral, Referral
from config import ApplicationConfig
import os
import requests
import string
import random
from flask_mail import Mail, Message
import base64
import cloudinary
import cloudinary.uploader
import cloudinary.api
from passlib.hash import bcrypt_sha256
cloudinary.config(
    cloud_name="dagw7pro6",
    api_key="761564937985964",
    api_secret="4GsZPO7aW5TvNNrkIAD4AgC_TTI"
)

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######### Initializing the app with the necessary packages #########
app = Flask(__name__)
# app_asgi = WsgiToAsgi(app)
app.config.from_object(ApplicationConfig)
CORS(app, allow_headers=True, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
migrate = Migrate(app, db)
server_session = Session(app)
db.init_app(app)
# with app.app_context():
#     db.drop_all()
#     db.create_all()
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######## Setting a concurent function to be run per request ########


@app.after_request
def add_cors_headers(response):
    frontend_domains = [
        'http://localhost:3000',
        'http://enetworksoffice.com.ng',
        'http://www.enetworksoffice.com.ng',
        'https://enetworksoffice.com.ng',
        'https://www.enetworksoffice.com.ng'
    ]

    origin = request.headers.get('Origin')
    if origin in frontend_domains:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
MARASOFT_API_BASE = "https://api.marasoftpay.live"
# Replace with your actual API key
MARASOFT_API_KEY = os.environ.get("MARASOFT_API_KEY")
####################################################################
####################################################################
####################################################################
######### Function to Handle the save profile Image Upload #########
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'profile_images')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


VALID_STATES = [
    'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa',
    'Benue', 'Borno', 'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti',
    'Enugu', 'FCT',  # Added FCT here
    'Gombe', 'Imo', 'Jigawa', 'Kaduna', 'Kano', 'Katsina',
    'Kebbi', 'Kogi', 'Kwara', 'Lagos', 'Nasarawa', 'Niger', 'Ogun',
    'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers', 'Sokoto', 'Taraba',
    'Yobe', 'Zamfara'
]

####################################################################
####################################################################
####################################################################
####################################################################
################## Function to save profile Image ##################


def upload_image_to_cloudinary(image):
    # Upload the image to Cloudinary
    result = cloudinary.uploader.upload(
        image,
        quality='auto:low',  # Set compression quality
    )
    #

    # Get the public URL of the uploaded image from the Cloudinary response
    image_url = result['url']

    return image_url

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


def require_role(role_names):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.filter_by(id=user_id).first()
            if not user or user.role.role_name not in role_names:
                return jsonify(message='Insufficient permissions'), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def has_role(user_id, roles):
    user = User.query.get(user_id)
    if user and user.role:
        return user.role.role_name in roles
    return False

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
# Function to generate OTP


def generate_otp():
    return ''.join(random.choices('0123456789', k=6))
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
# Function to send OTP to user's email


# @app.route("/send_email/<email>/<otp>", methods=["GET"])
def send_otp_to_email_for_reset(email, otp):
    subject = "E-networksCommunity Reset Password"

    msg_body = f"Dear user,\n\n" \
               f"Verify your Email: {email}\n" \
               f"Your OTP for password reset is: {otp}\n\n" \
               f"Please use this OTP to reset your password. If you didn't create this Request, " \
               f"you can ignore this email.\n\n" \
               f"Thank you!"

    try:
        result = send_email_with_otp(
            email, subject, 'verify_email', otp=otp, msg_body=msg_body)
        if result:
            return "Email sent.....", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500

# @app.route("/send_email/<email>/<otp>", methods=["GET"])


def send_reciept_to_user(email, user_name):
    subject = "E-networks Digital Card Receipt"

    try:
        result = send_email_with_no_otp(
            email, subject, 'reciept', user_name=user_name)
        if result:
            return "Email sent successfully", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500
####################################################################
####################################################################
####################################################################


def send_email_with_otp(to, subject, template, otp, **kwargs):
    msg = Message(subject, recipients=[to], sender=app.config['MAIL_USERNAME'])
    msg.body = "Hello"
    msg.html = render_template(
        template + '.html', user_email=to, otp=otp, **kwargs)

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(e)
        return False


def send_email_with_no_otp(to, subject, template, user_name, **kwargs):
    msg = Message(subject, recipients=[to], sender=app.config['MAIL_USERNAME'])
    msg.html = render_template(
        template + '.html', user_name=user_name, **kwargs)

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(e)
        return False

####################################################################
####################################################################
####################################################################
# Function to send OTP to user's email


def send_otp_to_email_for_verify(email, otp):
    subject = "E-networksCommunity Verify Email"

    try:
        result = send_email_with_otp(email, subject, 'verify_email', otp=otp)
        if result:
            return "Email sent successfully", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


@app.route('/')
def hello_world():
    return 'Hello from Koyeb'
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


def generate_referral_code():
    # Generate a random string of 6 characters (upper case letters and digits)
    letters_and_digits = string.ascii_uppercase + string.digits
    while True:
        referral_code = ''.join(random.choices(letters_and_digits, k=6))
        # Check if the referral code already exists in the database
        existing_user = User.query.filter_by(
            referral_code=referral_code).first()
        if not existing_user:
            break
    return referral_code
####################################################################
####################################################################
####################################################################
####################################################################
############################## Routes ##############################
####################################################################


@app.route("/profile_images/<filename>", methods=["GET"])
def serve_profile_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


@app.route('/submit_form', methods=['POST'])
@jwt_required()
def submit_form():
    try:
        current_user_id = get_jwt_identity()

        # Check if the current user is logged in
        if not current_user_id:
            return jsonify({"message": "User not logged in"}), 401

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        form_data = request.form
        signature_image = request.files.get('signature')
        profile_image = request.files.get('profile_image')
        passport_photo = request.files.get('passport_photo')
        guarantor_photo = request.files.get('guarantor_passport')

        if not signature_image or not profile_image or not passport_photo or not guarantor_photo:
            return jsonify(message="One or more required files not provided in the request"), 400

        required_fields = ['name', 'address', 'bvn', 'nin', 'agent_email', 'agent_card_number',
                           'gender', 'guarantor_name', 'guarantor_phone_number', 'guarantor_bvn', 'guarantor_nin',
                           'guarantor_address', 'date_of_birth', 'phone_number']

        for field in required_fields:
            if field not in form_data:
                return jsonify({"message": f"Missing required field: {field}"}), 400

        # Update user attributes based on provided data
        user.full_name = form_data.get('name')
        user.address = form_data.get('address')
        user.bvn = form_data.get('bvn')
        user.nin = form_data.get('nin')
        user.agent_email = form_data.get('agent_email')
        user.agent_card_no = form_data.get('agent_card_number')
        user.gender = form_data.get('gender')
        user.guarantor_name = form_data.get('guarantor_name')
        user.guarantor_phone_number = form_data.get('guarantor_phone_number')
        user.guarantor_bvn = form_data.get('guarantor_bvn')
        user.guarantor_nin = form_data.get('guarantor_nin')
        user.guarantor_address = form_data.get('guarantor_address')
        user.date_of_birth = datetime.strptime(
            form_data.get('date_of_birth'), '%Y-%m-%d').date()
        user.phone_number = form_data.get('phone_number')

        # Upload images to Cloudinary
        user.signature = cloudinary.uploader.upload(signature_image)['url']
        user.profile_image = cloudinary.uploader.upload(profile_image)['url']
        user.passport_photo = cloudinary.uploader.upload(passport_photo)['url']
        user.guarantor_passport = cloudinary.uploader.upload(guarantor_photo)[
            'url']

        db.session.commit()

        return jsonify(message="Form submitted successfully"), 200

    except Exception as e:
        return jsonify(message=str(e)), 500


# @app.route('/create_users_from_form', methods=['GET'])
# def create_users_from_form():
#     forms = Form.query.all()

#     for form in forms:
#         # Check if the user with the given email already exists
#         existing_user = User.query.filter_by(email=form.email).first()
#         if existing_user:
#             print(f"User with email '{form.email}' already exists. Skipping.")
#             continue

#         # Generate a unique staff ID based on the specified pattern
#         staff_id = f"{form.agent_card_no[:4]}{form.phone_number[-4:]}"

#         # Hash the password of the user before creating the user
#         hashed_password = bcrypt_sha256.hash(form.password)

#         # Create a new user using the Form data
#         new_user = User(
#             staff_id=staff_id,
#             full_name=form.full_name,
#             email=form.email,
#             password=hashed_password,
#             phone_number=form.phone_number,
#             bvn=form.bvn,
#             nin=form.nin,
#             agent_email=form.agent_email,
#             agent_card_no=form.agent_card_no,
#             address=form.address,
#             gender=form.gender,
#             date_of_birth=form.date_of_birth,
#             guarantor_name=form.guarantor_name,
#             guarantor_phone_number=form.guarantor_phone_number,
#             guarantor_bvn=form.guarantor_bvn,
#             guarantor_nin=form.guarantor_nin,
#             guarantor_address=form.guarantor_address,
#             guarantor_passport=form.guarantor_passport,
#             created_at=form.created_at,
#             modified_at=form.modified_at,
#             profile_image=form.profile_image,
#             is_email_verified=form.is_email_verified,
#             office_status=form.office_status,
#             # ... (add other fields as needed)
#         )

#         # Add the new user to the database
#         db.session.add(new_user)
#         db.session.commit()

#         try:
#             # Initialize the Referral table for the new user
#             referral_data = Referral(
#                 user_id=new_user.id, daily_target=0, weekly_target=0, monthly_target=0)
#             db.session.add(referral_data)
#             db.session.commit()

#         except IntegrityError as e:
#             db.session.rollback()
#             print(f"IntegrityError: {e}")
#             print(
#                 f"Referral data already exists for user with email '{form.email}'. Skipping.")

#     return jsonify({"message": "Users created successfully"}), 201


@app.route('/login', methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None or not bcrypt_sha256.verify(password, user.password):
        return jsonify({"message": "Wrong email or password"}), 401

    # Create the access token with the user ID as the identity
    access_token = create_access_token(identity=str(user.id))

    # Return the access token and user role as JSON response
    return jsonify(message="Logged in successfully", access_token=access_token), 200


@app.route('/edit-user', methods=['PATCH'])
@jwt_required()
def edit_user():
    try:
        current_user_id = get_jwt_identity()

        user = User.query.get(current_user_id)
        if not user:
            return jsonify(message="User not found"), 404

        # Get the data from the PATCH request
        data = request.form.to_dict()

        # Check if the current user has permission to edit this user (optional, if needed)
        # For example, you can check if the current user is the same as the user being edited.

        # Update user attributes based on provided data
        if 'password' in data:
            new_password = data.get("password")
            hashed_password = bcrypt_sha256.hash(new_password)
            user.password = hashed_password

        if 'address' in data:
            address = data.get("address")
            user.address = address

        if 'phoneNumber' in data:
            phoneNumber = data.get("phoneNumber")
            user.phone_number = phoneNumber

        if 'email' in data:
            email = data.get("email")
            user.email = email

        db.session.commit()

        return jsonify(message=f"Your user data updated successfully"), 200

    except Exception as e:
        return jsonify(message="An error occurred", error=str(e)), 500


@app.route('/create_users_batch', methods=['POST'])
def create_users_batch():
    try:
        data = request.get_json()

        if not isinstance(data, list):
            return jsonify({"error": "Invalid input format. Expected a list of emails."}), 400

        created_users = []

        for email in data:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                created_users.append(
                    {"email": email, "message": "User already exists. Skipping."})
                continue

            password = "0000-0000"
            hashed_password = bcrypt_sha256.hash(password)

            # Create a new user
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            # Create a referral for the new user
            referral_data = Referral(
                user_id=new_user.id, daily_target=0, weekly_target=0, monthly_target=0)
            db.session.add(referral_data)
            db.session.commit()

            created_users.append(
                {"email": email, "message": "User and referral created successfully."})

        return jsonify({"created_users": created_users}), 201

    except Exception as e:
        return jsonify({"error": "An error occurred while processing the request."}), 500


@app.route('/dashboard', methods=["GET"])
@jwt_required()
def dashboard():
    # Get the user identity from the JWT token
    current_user_id = get_jwt_identity()

    # Query the user information from the database
    user = User.query.filter_by(id=current_user_id).first()

    if user is None:
        return jsonify({"message": "User not found"}), 404

    # Get user data using the to_dict method
    dashboard_data = user.to_dict()

    return jsonify(dashboard_data), 200


@app.route('/submit_referral', methods=['POST'])
@jwt_required()
def submit_referral():
    current_user_id = get_jwt_identity()

    # Ensure the current user exists
    current_user = User.query.get(current_user_id)
    if not current_user:
        return jsonify({"message": "User not found"}), 404

    # Parse details from the request
    referred_user_name = request.json.get('referred_user_name')
    referred_user_email = request.json.get('referred_user_email')
    referred_user_card_number = request.json.get('referred_user_card_number')

    # Check if the referred user email already exists
    existing_referral = SuccessfulReferral.query.filter_by(
        referred_user_email=referred_user_email).first()
    if existing_referral:
        return jsonify({"message": "Referral already submitted"}), 400

    # Make API request to validate referred user email
    # Replace with the actual API endpoint
    api_url = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
    api_payload = {'email': referred_user_email}
    api_response = requests.post(api_url, data=api_payload)

    if api_response.status_code == 200:
        api_data = api_response.json()
        if api_data['status'] and api_data['agent_details']['email'] == current_user.email:
            # Create a new SuccessfulReferral instance
            new_referral = SuccessfulReferral(
                referrer_id=current_user.id,
                referred_user_name=referred_user_name,
                referred_user_email=referred_user_email,
                referred_user_card_number=referred_user_card_number,
                validity=True,
                timestamp=datetime.utcnow()
            )

            # Add the new referral to the database
            db.session.add(new_referral)
            db.session.commit()

            # Update the Referral table
            referral = Referral.query.filter_by(
                user_id=current_user.id).first()
            if referral:
                referral.total_referrals = referral.total_referrals + 1
                db.session.commit()

            return jsonify({"message": "Referral submitted successfully"}), 201
        else:
            return jsonify({"message": "Invalid referral. Your email and the email shown to refer the user are different."}), 400
    else:
        return jsonify({"message": "Failed to validate email with external API"}), 500


@app.route('/successful_referrals', methods=['GET'])
@jwt_required()
def get_successful_referrals_route():
    try:
        user_id = get_jwt_identity()
        # Check if the user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Get successful referrals for the user using the class method
        referrals_data = SuccessfulReferral.get_successful_referrals(user.id)

        return jsonify({"successful_referrals": referrals_data})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/weekly_work_done', methods=['GET'])
@jwt_required()
def get_weekly_work_done_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get weekly work done for the user
        weekly_work_done = SuccessfulReferral.get_weekly_work_done(current_user_id)
        return jsonify({"weekly_work_done": weekly_work_done})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/monthly_work_done', methods=['GET'])
@jwt_required()
def get_monthly_work_done_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get monthly work done for the user
        monthly_work_done = SuccessfulReferral.get_monthly_work_done(current_user_id)
        return jsonify({"monthly_work_done": monthly_work_done})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/total_referrals_count', methods=['GET'])
@jwt_required()
def get_total_referrals_count_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get total referrals count for the user
        total_referrals_count = SuccessfulReferral.get_total_referrals_count(
            current_user_id)
        return jsonify({"total_referrals_count": total_referrals_count})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/user/referral', methods=['GET'])
@jwt_required()
def get_user_referral():
    try:
        # Get the current user's identity from the JWT token
        current_user_id = get_jwt_identity()

        # Ensure the current user exists
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({"message": "User not found"}), 404

        # Fetch the referral data for the user
        referral_data = Referral.query.filter_by(
            user_id=current_user.id).first()

        # Check if the referral data exists
        if not referral_data:
            return jsonify({"message": "Referral data not found for the user"}), 404

        # Convert referral data to dictionary
        referral_dict = referral_data.to_dict()

        return jsonify({"referral_data": referral_dict}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500


AVAILABLE_POSITIONS = [
    'State Managers',
    'State Asst Manager',
    'State Admin Sec',
    'State Operations Manager',
    'State Media and Public Relations Officer',
    'State Legal Asst',
    'State Finance Officer',
    'State Tech Officer',
    'State Community Relations Officer',
    'State Product Dev Officer',
    'State Business Development Officer',
    'State Personnel Manager',
    'State Desk Officer( NGO DESK OFFICE)',
    'Dep Desk Officer',
    'Gen Secretary',
    'Asst Gen Secretary',
    'Financial Secretary',
    'Treasurer',
    'Information Officer ( Public and Traditional)',
    'Asst Information Officer( Social Media)',
    'Legal Adviser',
    'Women Affairs Officer',
    'Youth Affairs Officer',
    'Organising Officer',
    'LG Desk Officer',
    'Dep LG Desk Officer',
    'LG Gen Secretary',
    'LG Asst Gen Secretary',
    'LG Financial Secretary',
    'LG Treasurer',
    'LG Information Officer ( Public and Traditional)',
    'LG Asst Information Officer( Social Media)',
    'LG Legal Adviser',
    'LG Women Affairs Officer',
    'LG Youth Affairs Officer',
    'LG Organising Officer',
    'LG Business Manager/Coordinator',
    'LG Asst Business Manager/Coordinator ',
    'LG Admin Sec',
    'LG Operations Manager',
    'LG Media and Public Relations Officer',
    'LG Legal Asst',
    'LG Finance Officer',
    'LG Tech Officer',
    'LG Community Relations Officer',
    'LG Product Dev Officer',
    'LG Business Development Officer',
    'LG Personnel Manager',
]

GENDER = ["Male", "Female"]


if __name__ == "__main__":
    app.run(debug=True)
