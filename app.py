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
        'https://www.enetworksagencybanking.com.ng',
        'https://enetworks-update.vercel.app',
        'https://jobs-admin.vercel.app',
        'http://enetworksoffice.com.ng/',
        'https://enetworksoffice.com.ng/'
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
def submit_form():
    form_data = request.form
    signature_image = request.files.get('signature')
    profile_image = request.files.get('profile_image')
    passport_photo = request.files.get('passport_photo')
    guarantor_photo = request.files.get('guarantor_passport')

    if not form_data or not signature_image or not profile_image or not passport_photo or not guarantor_photo:
        return jsonify(message="No data or files provided in the request"), 400

    required_fields = ['name', 'address', 'email', 'bvn', 'nin', 'agent_email', 'agent_card_number',
                       'gender', 'guarantor_name', 'guarantor_phone_number', 'guarantor_bvn', 'guarantor_nin',
                       'guarantor_address', 'date_of_birth', 'phone_number']

    for field in required_fields:
        if field not in form_data:
            return jsonify({"message": f"Missing required field: {field}"}), 400

    name = form_data.get('name')
    address = form_data.get('address')
    email = form_data.get('email')
    date_of_birth_raw = form_data.get('date_of_birth')
    date_of_birth = datetime.strptime(date_of_birth_raw, '%Y-%m-%d').date()

    try:
        # Upload images to Cloudinary
        signature_url = cloudinary.uploader.upload(signature_image)['url']
        profile_image_url = cloudinary.uploader.upload(profile_image)['url']
        passport_photo_url = cloudinary.uploader.upload(passport_photo)['url']
        guarantor_photo_url = cloudinary.uploader.upload(guarantor_photo)[
            'url']

        new_form = Form(
            full_name=name,
            address=address,
            email=email,
            bvn=form_data.get('bvn'),
            nin=form_data.get('nin'),
            agent_email=form_data.get('agent_email'),
            agent_card_no=form_data.get('agent_card_number'),
            gender=form_data.get('gender'),
            guarantor_name=form_data.get('guarantor_name'),
            guarantor_phone_number=form_data.get('guarantor_phone_number'),
            guarantor_bvn=form_data.get('guarantor_bvn'),
            guarantor_nin=form_data.get('guarantor_nin'),
            guarantor_address=form_data.get('guarantor_address'),
            date_of_birth=date_of_birth,
            phone_number=form_data.get('phone_number'),
            signature=signature_url,
            profile_image=profile_image_url,
            passport_photo=passport_photo_url,
            guarantor_passport=guarantor_photo_url
        )

        db.session.add(new_form)
        db.session.commit()

        return jsonify(message="Form submitted successfully"), 200

    except Exception as e:
        return jsonify(message=str(e)), 500


@app.route('/create_users_from_form', methods=['GET'])
def create_users_from_form():
    forms = Form.query.all()

    for form in forms:
        # Check if the user with the given email already exists
        existing_user = User.query.filter_by(email=form.email).first()
        if existing_user:
            print(f"User with email '{form.email}' already exists. Skipping.")
            continue

        # Generate a unique staff ID based on the specified pattern
        staff_id = f"{form.agent_card_no[:4]}{form.phone_number[-4:]}"

        # Hash the password of the user before creating the user
        hashed_password = bcrypt_sha256.hash(form.password)

        # Create a new user using the Form data
        new_user = User(
            staff_id=staff_id,
            full_name=form.full_name,
            email=form.email,
            password=hashed_password,
            phone_number=form.phone_number,
            bvn=form.bvn,
            nin=form.nin,
            agent_email=form.agent_email,
            agent_card_no=form.agent_card_no,
            address=form.address,
            gender=form.gender,
            date_of_birth=form.date_of_birth,
            guarantor_name=form.guarantor_name,
            guarantor_phone_number=form.guarantor_phone_number,
            guarantor_bvn=form.guarantor_bvn,
            guarantor_nin=form.guarantor_nin,
            guarantor_address=form.guarantor_address,
            guarantor_passport=form.guarantor_passport,
            created_at=form.created_at,
            modified_at=form.modified_at,
            profile_image=form.profile_image,
            is_email_verified=form.is_email_verified,
            office_status=form.office_status,
            # ... (add other fields as needed)
        )

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        try:
            # Initialize the Referral table for the new user
            referral_data = Referral(
                user_id=new_user.id, daily_target=0, weekly_target=0, monthly_target=0)
            db.session.add(referral_data)
            db.session.commit()

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {e}")
            print(
                f"Referral data already exists for user with email '{form.email}'. Skipping.")

    return jsonify({"message": "Users created successfully"}), 201


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


@app.route('/users/<user_id>', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_user_by_id(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = user.to_dict()  # Convert User object to a dictionary

    return jsonify(user_data)


@app.route('/users/<user_id>/referrals', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_user_referrals(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    referral_list = user.get_referral_list()

    return jsonify(referral_list)


@app.route('/upload', methods=['POST'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def upload_image():
    try:
        print("Started uploading")
        image = request.files['image']
        if not image:
            return jsonify({'error': 'No image provided'}), 400

        # Upload the image to Cloudinary and set the compression settings
        result = cloudinary.uploader.upload(
            image,
            quality='auto:low',  # Set compression quality
        )

        return jsonify({'url': result['secure_url']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/logout", methods=["POST"])
def logout():
    # Clear the token on the client-side (e.g., remove from local storage or delete the token cookie)
    # No server-side token handling is required
    return jsonify(message="Logged out successfully"), 200


@app.route('/referral-history', methods=['GET'])
def get_referral_history():
    # Get all users who have referred others
    referrers = User.query.filter(User.referred_users.any()).all()

    referral_history_list = []

    for referrer in referrers:
        # Get the list of users referred by this referrer
        referred_users = referrer.referred_users.all()

        # Iterate through referred users and construct the data for each referral
        for referred_user in referred_users:
            referral_data = {
                'referrer': f"{referrer.first_name} {referrer.last_name}",
                'referred': f"{referred_user.first_name} {referred_user.last_name}",
                'date': referred_user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            referral_history_list.append(referral_data)

    return jsonify(referral_history_list), 200


@app.route('/admin-dashboard')
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def admin_dashboard():
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        # Get total number of registered users
        total_users = User.get_total_registered_users()

        # Get total number of registered executives
        total_executives = User.query.filter_by(role_id=3).count()

        # Get total number of registered interns
        total_interns = User.query.filter_by(role_id=5).count()

        # Get total number of registered mobilizers
        total_mobilizers = User.query.filter_by(role_id=4).count()

        # Get total number of referrals
        total_referrals = SuccessfulPayment.query.count()

        # Get referral data
        referrals = []
        for payment in SuccessfulPayment.query.all():
            referrer = db.session.query(User).filter_by(
                id=payment.user_id).first()
            referred = db.session.query(User).filter_by(
                id=referrer.referred_by_id).first()

            referrer_name = f"{referrer.first_name} {referrer.last_name}"
            referred_name = f"{referred.first_name} {referred.last_name}" if referred else "No Referral"

            referrals.append({
                'referred_name': referred_name,
                'referrer_name': referrer_name
            })

        # Get details for all interns, mobilizers, and executives
        interns_data = get_role_data(5)
        mobilizers_data = get_role_data(4)
        executives_data = get_role_data(3)

        # Construct the response JSON
        response = {
            'name': current_user.first_name + ' ' + current_user.last_name,
            'phone_number': current_user.phone_number,
            'email': current_user.email,
            'role': current_user.role.role_name,
            'total_users': total_users,
            'total_executives': total_executives,
            'total_interns': total_interns,
            'total_mobilizers': total_mobilizers,
            'total_referrals': total_referrals,
            'referrals': referrals,
            'interns_data': interns_data,
            'mobilizers_data': mobilizers_data,
            'executives_data': executives_data,
            'profile_image': current_user.profile_image
        }

        return jsonify(response), 200
    except Exception as e:
        print("Error fetching admin dashboard:", str(e))
        return jsonify(message="An error occurred"), 500


def get_role_data(role_id):
    role_data = []
    for user in User.query.filter_by(role_id=role_id).all():
        role_data.append({
            'name': user.first_name + ' ' + user.last_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'state': user.state,
            'address': user.address,
            'has_paid': user.has_paid
        })
    return role_data


@app.route('/create-admin', methods=['POST'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def create_admin():
    try:
        email = "Admin@Enet.com"
        password = email  # Use the email as the password for simplicity
        first_name = "To Be Edited"
        last_name = "To Be Edited"
        phone_number = "To Be Edited"
        address = "To Be Edited"

        role_name = "Admin"  # Assuming 'Executives' is the role name for executives

        # Check if the executive already exists
        existing_admin = User.query.filter_by(email=email).first()
        if not existing_admin:
            # Create a new executive user
            role = Role.query.filter_by(role_name=role_name).first()
            if role:
                new_admin = User(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=bcrypt_sha256.hash(password),
                    phone_number=phone_number,
                    role=role,
                    state="Null",  # Set the state to the current state being iterated
                    address=address,
                    local_government="To Be Edited",
                    is_email_verified=True,  # Mark email as verified for simplicity
                    enairaId="To be Edited",
                    bank_name="To be Added"
                )

                db.session.add(new_admin)
                db.session.commit()

        return jsonify(message="Admin created successfully"), 201
    except Exception as e:
        db.session.rollback()
        print("Error creating Admin:", str(e))
        return jsonify(message="Failed to create Admin"), 500


@app.route('/edit/<user_id>', methods=['PUT'])
@jwt_required()
def edit_user_with_id(user_id):
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return jsonify({'message': 'Invalid user'}), 401

        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Update user data based on the request JSON
        updated_data = request.get_json()
        if 'first_name' in updated_data:
            user.first_name = updated_data['first_name']
        if 'last_name' in updated_data:
            user.last_name = updated_data['last_name']
        if 'email' in updated_data:
            user.email = updated_data['email']
        if 'phone_number' in updated_data:
            user.phone_number = updated_data['phone_number']
        if 'profile_image' in updated_data:
            user.profile_image = updated_data['profile_image']
        if 'has_paid' in updated_data:
            if user.has_paid:
                return jsonify({'message': 'User has already paid'}), 400

            # If the payment status is being updated to True
            if updated_data['has_paid'] and not user.has_paid:
                user.has_paid = True

                # Check if the user has a referrer and update their earnings
                if user.referred_by_id:
                    referrer = User.query.get(user.referred_by_id)
                    if referrer:
                        if referrer.role and referrer.role.role_name in ("Mobilizer", "Intern"):
                            # Distribute earnings based on referrer's role
                            if referrer.role.role_name == "Mobilizer":
                                referrer.earnings += 100
                            elif referrer.role.role_name == "Intern":
                                referrer.earnings += 100
                                referrer.reserved_earnings += 100

                            # Update earnings for executives in the same state as the user
                            if user.state:
                                executives = User.query.filter_by(
                                    state=user.state, role_id=3).all()
                                for executive in executives:
                                    executive.earnings += 50
                                    db.session.add(executive)

                            # Save changes for referrer
                            db.session.add(referrer)

        if 'has_not_paid' in updated_data:
            user.has_paid = False

        if 'earnings' in updated_data:
            user.earnings = updated_data['earnings']
            if user.referred_by_id:
                referrer = User.query.get(user.referred_by_id)
                if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                    referrer.earnings += 100
                    db.session.add(referrer)

        if 'is_email_verified' in updated_data:
            user.is_email_verified = updated_data['is_email_verified']
        if 'referrer' in updated_data:
            user.referred_by_id = updated_data['referrer']

            if user.has_paid:
                referrer = User.query.get(user.referred_by_id)
                if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                    referrer.earnings += 100
                    db.session.add(referrer)
                elif referrer and referrer.role and referrer.role.role_name == "Intern":
                    referrer.earnings += 100
                    referrer.reserved_earnings += 100
                    db.session.add(referrer)

        if 'no_referrer' in updated_data:
            user.referred_by_id = None
        if 'account' in updated_data:
            user.account = updated_data['account']
        if 'role_id' in updated_data:
            user.role_id = updated_data['role_id']
        if 'password' in updated_data:
            new_password = updated_data['password']
            hashed_password = bcrypt_sha256.hash(new_password)
            user.password = hashed_password

        db.session.commit()

        return jsonify({'message': f'User data updated successfully for {user.email}'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/delete-user/<user_id>', methods=['DELETE'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message=f'User {user.email} deleted successfully')
    else:
        return jsonify(message='User not found'), 404


@app.route('/download-interns-csv', methods=['GET'])
def download_interns_csv():
    # Query the database to get all users with the 'Intern' role and who have paid
    interns = User.query.filter_by(role_id=4, has_paid=True).all()

    # Create a list of dictionaries containing data for each intern
    intern_data = []
    for intern in interns:
        intern_info = {
            'First Name': intern.first_name,
            'Last Name': intern.last_name,
            'email': intern.email,
            'paid': intern.has_paid,
            'Phone Number': intern.phone_number,
            'Profile Image': intern.profile_image,
            'Address': intern.address,
            'state': intern.state,
            'Referred By': intern.referred_by_id,
        }
        intern_data.append(intern_info)

    # Create a DataFrame from the list of dictionaries
    df = pd.DataFrame(intern_data)

    # Create a BytesIO buffer to hold the CSV file
    csv_buffer = BytesIO()

    # Convert the DataFrame to a CSV string and write it to the buffer
    df.to_csv(csv_buffer, index=False, encoding="utf-8")

    # Set the buffer's position to the beginning
    csv_buffer.seek(0)

    # Send the CSV file as a response with appropriate headers
    return send_file(
        csv_buffer,
        as_attachment=True,
        download_name='paid-mobilizers.csv',
        mimetype='text/csv'
    )


@app.route('/download-csv1', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def download_csv1():
    # Create a ZIP archive to store CSV files
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Iterate through role IDs (4 for mobilizers, 5 for interns)
        for role_id in [4, 5]:
            # Create a directory in the ZIP archive for each role
            role_directory = 'Mobilizers' if role_id == 4 else 'Interns'
            for state in VALID_STATES:
                # Query the database to get users of the specified role in the current state who have paid
                users = User.query.filter_by(
                    role_id=role_id, state=state, has_paid=True).all()

                # Create a list of dictionaries containing data for each user
                user_data = []
                for user in users:
                    user_info = {
                        'First Name': user.first_name,
                        'Last Name': user.last_name,
                        'Email': user.email,
                        'Paid': user.has_paid,
                        'Phone Number': user.phone_number,
                        'Profile Image': user.profile_image,
                        'Address': user.address,
                        'State': user.state,
                        'Referred By': user.referred_by_id,
                    }
                    user_data.append(user_info)

                if user_data:
                    # Create a DataFrame from the list of dictionaries
                    df = pd.DataFrame(user_data)

                    # Create a BytesIO buffer to hold the CSV file
                    csv_buffer = BytesIO()

                    # Convert the DataFrame to a CSV string and write it to the buffer
                    df.to_csv(csv_buffer, index=False, encoding="utf-8")

                    # Set the buffer's position to the beginning
                    csv_buffer.seek(0)

                    # Define the file name based on the role and state
                    file_name = f'{role_directory}/{state}.csv'

                    # Add the CSV file to the ZIP archive
                    zipf.writestr(file_name, csv_buffer.read())

    # Set the ZIP archive's position to the beginning
    zip_buffer.seek(0)

    # Send the ZIP archive as a response with appropriate headers
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name='user_data.zip',
        mimetype='application/zip'
    )


@app.route('/download-csv', methods=['GET'])
def download_csv():
    # Create separate CSV files for interns and mobilizers, grouped by state
    # Iterate through role IDs (4 for mobilizers, 5 for interns)
    for role_id in [4, 5]:
        for state in VALID_STATES:
            # Query the database to get users of the specified role in the current state who have paid
            users = User.query.filter_by(
                role_id=role_id, state=state, has_paid=True).all()

            # Create a list of dictionaries containing data for each user
            user_data = []
            for user in users:
                user_info = {
                    'First Name': user.first_name,
                    'Last Name': user.last_name,
                    'Email': user.email,
                    'Paid': user.has_paid,
                    'Phone Number': user.phone_number,
                    'Profile Image': user.profile_image,
                    'Address': user.address,
                    'State': user.state,
                    'Referred By': user.referred_by_id,
                }
                user_data.append(user_info)

            if user_data:
                # Create a DataFrame from the list of dictionaries
                df = pd.DataFrame(user_data)

                # Create a BytesIO buffer to hold the CSV file
                csv_buffer = BytesIO()

                # Convert the DataFrame to a CSV string and write it to the buffer
                df.to_csv(csv_buffer, index=False, encoding="utf-8")

                # Set the buffer's position to the beginning
                csv_buffer.seek(0)

                # Define the file name based on the role and state
                file_name = f'{state}_{"Mobilizers" if role_id == 4 else "Interns"}.csv'

                # Send the CSV file as a response with appropriate headers
                return send_file(
                    csv_buffer,
                    as_attachment=True,
                    download_name=file_name,
                    mimetype='text/csv'
                )

    # Return a response if no data was found
    return "No data found for download."


@app.route('/download-txt', methods=['GET'])
def download_txt():
    # Create a dictionary to store paid users grouped by state and role
    user_data_by_state = {}

    # Iterate through role IDs (4 for mobilizers, 5 for interns)
    for role_id in [4, 5]:
        for state in VALID_STATES:
            # Query the database to get users of the specified role in the current state who have paid
            users = User.query.filter_by(
                role_id=role_id, state=state, has_paid=True).all()

            # Extract names and phone numbers and store them in the dictionary
            if users:
                user_info = [
                    f'{user.first_name} {user.last_name}: {user.phone_number}' for user in users]
                if state not in user_data_by_state:
                    user_data_by_state[state] = {}
                user_data_by_state[state][role_id] = user_info

    # Create a ZIP archive to store TXT files
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for state, user_data in user_data_by_state.items():
            # Create separate TXT files for each state
            for role_id, users in user_data.items():
                role_directory = 'Mobilizers' if role_id == 4 else 'Interns'
                txt_content = '\n'.join(users)

                # Define the file name based on the state and role
                file_name = f'{role_directory}/{state}_{"Mobilizers" if role_id == 4 else "Interns"}.txt'

                # Write the TXT file to the ZIP archive
                zipf.writestr(file_name, txt_content)

    # Set the ZIP archive's position to the beginning
    zip_buffer.seek(0)

    # Send the ZIP archive as a response with appropriate headers
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name='user_data.zip',
        mimetype='application/zip'
    )


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
