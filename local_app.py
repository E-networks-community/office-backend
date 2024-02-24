from functools import wraps
import json
import uuid
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, session
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from sqlalchemy.exc import SQLAlchemyError
from models import SuccessfulPayment, OTP
from config import ApplicationConfig
from models import Role, db, User, create_roles
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
#     create_roles()
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######## Setting a concurent function to be run per request ########


@app.after_request
def add_cors_headers(response):
    # Replace with your frontend domain
    frontend_domain = 'http://localhost:3000'
    # frontend_domain = 'https://www.enetworksagencybanking.com.ng'
    response.headers['Access-Control-Allow-Origin'] = frontend_domain
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


####################################################################
####################################################################
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


@app.route('/agent/register', methods=['POST'])
def register_agent():
    return register_user(role_name='Agent')


@app.route('/intern/register', methods=['POST'])
def register_intern():
    return register_user(role_name='Intern')


@app.route('/mobilizer/register', methods=['POST'])
def register_mobilizer():
    return register_user(role_name='Mobilizer')


def register_user(role_name, referrer_id=None):
    try:
        # Begin a new database transaction
        with app.app_context():
            # Use request.form.to_dict() to get the form data (excluding files)
            data = request.form.to_dict()
            profile_image = request.files.get('profile_image')

            if not data:
                return jsonify(message='No data provided in the request'), 400

            if not profile_image:
                return jsonify(message='Profile image is required'), 400

            # Extract user registration data from the JSON request
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            password = data.get('password')
            phone_number = data.get('phone_number')
            referral_code = data.get('referral_code')

            # New fields
            state = data.get('state')
            local_government_area = data.get('local_government_area')
            address = data.get('address')
            account = data.get('account')
            bankName = data.get('bankName')
            enairaId = data.get('enaira_Id', None)

            if not all([first_name, last_name, email, password, phone_number, state, local_government_area, address, account, bankName]):
                return jsonify(message='Missing required fields in the request'), 400

            # Check if the email is already in use
            if User.query.filter_by(email=email).first():
                return jsonify(message='Email already registered'), 409

            # Validate state
            if state not in VALID_STATES:
                return jsonify(message='Invalid state provided'), 400

            # Check if the referral code exists and get the referrer user

            if referral_code:
                referrer = User.query.filter_by(
                    referral_code=referral_code).first()
                if not referrer:
                    return jsonify(message='Invalid referral code provided'), 400
            else:
                referrer = None

            # Get the appropriate role based on the role_name provided
            role = Role.query.filter_by(role_name=role_name).first()
            if not role:
                return jsonify(message=f'Invalid role_name provided: {role_name}'), 400

            # Generate a unique referral code for the new user
            hashed_password = bcrypt_sha256.hash(password)

            new_user_referral_code = generate_referral_code()

            new_user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=hashed_password,
                phone_number=phone_number,
                referral_code=new_user_referral_code,
                role=role,
                referred_by_id=referrer_id,
                state=state,
                local_government=local_government_area,
                address=address,
                enairaId=enairaId,
                account=account,
                bank_name=bankName
            )

            db.session.add(new_user)
            db.session.commit()

            if profile_image and allowed_file(profile_image.filename):
                # Upload the profile image to Cloudinary
                profile_image_url = upload_image_to_cloudinary(profile_image)
                new_user.profile_image = profile_image_url

            # Save the referral link before committing the user object
            new_user.referral_link = new_user.generate_referral_link()

            # Commit the user object with the referral link and profile image (if any)
            db.session.commit()

            email_verification_otp = generate_otp()

            otp = OTP(user_id=new_user.id, email=new_user.email,
                      otp=email_verification_otp)
            db.session.add(otp)
            db.session.commit()

            # Send the OTP to the user's email for verification
            send_otp_to_email_for_verify(
                new_user.email, email_verification_otp)

            # Save the OTP in the user's session for verification later
            identity = {"user_id": str(
                new_user.id), "email_verification_otp": email_verification_otp}
            access_token = create_access_token(identity=json.dumps(identity))

            return jsonify({"access_token": access_token, "role": new_user.role.role_name, "otp": email_verification_otp}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        print("Error during user registration:", str(e))
        return jsonify(message='Failed to register user. Please try again later.'), 500


@app.route('/login', methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None or not bcrypt_sha256.verify(password, user.password):
        return jsonify({"error": "Unauthorized"}), 401

    # Create the access token with the user ID as the identity
    access_token = create_access_token(identity=str(user.id))

    # Return the access token and user role as JSON response
    return jsonify({"access_token": access_token, "role": user.role.role_name}), 200


@app.route('/verify-email', methods=['POST'])
@jwt_required()
def verify_email():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify(message='User not found'), 404

        data = request.form
        email_verification_otp = data.get('otp')
        email = user.email

        if not email_verification_otp or not email:
            return jsonify(message='OTP and email fields are required'), 400

        # Get the OTP from the OTP table based on the user's email
        otp_entry = OTP.query.filter_by(user_id=user_id, email=email).first()

        if not otp_entry:
            return jsonify(message='OTP entry not found'), 404

        stored_otp = otp_entry.otp

        if stored_otp != email_verification_otp:
            return jsonify(message='Invalid OTP'), 401

        if user.is_email_verified:
            return jsonify(message="You have already verified your email"), 200

        # Mark the user's email as verified
        user.is_email_verified = True
        db.session.commit()

        # Remove the OTP entry from the OTP table after successful verification
        db.session.delete(otp_entry)
        db.session.commit()

        return jsonify(message='Email verified successfully'), 200

    except KeyError:
        return jsonify(message='Invalid JWT token'), 401
    except Exception as e:
        db.session.rollback()
        print("Error during email verification:", str(e))
        return jsonify(message='Failed to verify email. Please try again later.'), 500


# @app.route('/referral/<referral_code>', methods=['POST'])
# def register_with_referral(referral_code):
#     data = request.form.to_dict()
#     email = data.get('email')
#     password = data.get('password')
#     first_name = data.get('first_name')
#     last_name = data.get('last_name')
#     phone_number = data.get('phone_number')
#     profile_image = request.files.get('profile_image')

#     if not all([email, password, first_name, last_name, phone_number, profile_image]):
#         return jsonify(message='Missing required fields in the request'), 400

#     # Check if the referral code exists and get the referrer user
#     referrer = User.query.filter_by(referral_code=referral_code).first()
#     if not referrer:
#         return jsonify(message='Invalid referral code provided'), 400

#     if User.query.filter_by(email=email).first():
#         return jsonify(message='Email already registered'), 409

#     try:
#         # Call the register_user function with the role_name "Intern" and referrer_id
#         register_user("Intern", referrer.id)
#     except ValueError as e:
#         return jsonify(message=str(e)), 400

#     return jsonify(message="Register complete"), 200

@app.route('/referral/<referral_code>', methods=['POST'])
def register_with_referral(referral_code):
    data = request.form.to_dict()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_number = data.get('phone_number')
    profile_image = request.files.get('profile_image')

    if not all([email, password, first_name, last_name, phone_number, profile_image]):
        return jsonify(message='Missing required fields in the request'), 400

    # Check if the referral code exists and get the referrer user
    referrer = User.query.filter_by(referral_code=referral_code).first()
    if not referrer:
        return jsonify(message='Invalid referral code provided'), 400

    if User.query.filter_by(email=email).first():
        return jsonify(message='Email already registered'), 409

    # Check if the referrer's ID is set and not None
    if not referrer.id:
        return jsonify(message='Invalid referral link'), 400

    try:
        # Call the register_user function with the role_name "Intern" and referrer_id
        register_user("Intern", referrer.id)
    except ValueError as e:
        return jsonify(message=str(e)), 400

    return jsonify(message="Register complete"), 200


@app.route('/edit-user', methods=['PATCH'])
@jwt_required()
def edit_user():
    try:
        current_user_id = get_jwt_identity()

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get the data from the PATCH request
        data = request.form.to_dict()

        # Check if the current user has permission to edit this user (optional, if needed)
        # For example, you can check if the current user is the same as the user being edited.

        # Update user attributes based on provided data
        if 'password' in data:
            new_password = data.get("password")
            hashed_password = bcrypt_sha256.hash(new_password)
            user.password = hashed_password

        if 'email' in data:
            email = data.get("email")
            user.email = email

        if 'phone_number' in data:
            phone_number = data.get("phone_number")
            user.phone_number = phone_number

        if 'local_government_area' in data:
            lga = data.get("local_government_area")
            user.lga = lga

        if 'address' in data:
            address = data.get("address")
            user.address = address

        if 'account' in data:
            account = data.get("account")
            user.account = account

        # Commit the changes to the database
        db.session.commit()

        return jsonify({"message": f"User {current_user_id} data updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()

    print(f"This is the user ID: {user_id}")

    # Query the database to fetch the user's data
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify(message='User not found'), 404

    # Convert the user data to a dictionary using the to_dict() method from the User model
    user_data = user.to_dict()

    # Get the list of referred users and their email verification status
    referral_list = user.get_referral_list()
    # Add the referral list to the user data dictionary
    user_data['referral_list'] = referral_list
    # referral_history = user.get_referral_history()
    # user_data['recent_referral_history'] = referral_history

    # Return the user's data as a JSON response
    return jsonify(user_data), 200


@app.route('/resend-otp', methods=['POST'])
@jwt_required()  # Assuming you are using JWT for authentication
def resend_otp():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify(message='User not found'), 404

    # Generate a new OTP and update it in the database
    new_otp = generate_otp()
    otp_record = OTP.query.filter_by(user_id=user_id).first()
    if otp_record:
        otp_record.otp = new_otp
        # otp_record.timestamp = datetime.utcnow()  # Update the timestamp
    else:
        otp_record = OTP(user_id=user_id, email=user.email, otp=new_otp)
        db.session.add(otp_record)

    try:
        db.session.commit()

        # Send the new OTP to the user's email for verification
        send_otp_to_email_for_verify(user.email, new_otp)

        return jsonify(message=f'New OTP has been sent to your email {new_otp}'), 200
    except Exception as e:
        db.session.rollback()
        print("Error during OTP resend:", str(e))
        return jsonify(message='Failed to resend OTP. Please try again later.'), 500


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify(message='Email field is required'), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message='User not found'), 404

    # Generate OTP and send it to the user's email
    otp = generate_otp()
    send_otp_to_email_for_reset(email, otp)

    # Store the OTP in the user's session for verification later
    session['otp'] = otp
    session['user_id'] = user.id

    return jsonify(message='OTP sent to email'), 200


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    otp = data.get('otp')
    new_password = data.get('new_password')

    # Get the OTP and user ID from the session
    stored_otp = session.get('otp')
    user_id = session.get('user_id')

    if not otp or not new_password:
        return jsonify(message='OTP and new_password fields are required'), 400

    if stored_otp != otp:
        return jsonify(message='Invalid OTP'), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify(message='User not found'), 404

    # Update the user's password
    hashed_new_password = bcrypt.generate_password_hash(new_password)
    user.password = hashed_new_password
    db.session.commit()

    # Clear the OTP and user ID from the session
    session.pop('otp', None)
    session.pop('user_id', None)

    return jsonify(message='Password updated successfully'), 200


# @app.route('/users', methods=['GET'])
# def get_all_users():
#     users = User.query.all()
#     user_data = [{
#         'id': user.id,
#         # 'full_name': user.full_name,
#         'first_name': user.first_name,
#         'last_name': user.last_name,
#         'email': user.email,
#         'profile_image': user.profile_image,
#         'has_paid': user.has_paid,
#         'role': user.role.role_name,
#         'created_at': user.created_at,
#         'modified_at': user.modified_at,
#         "is_email_verified": user.is_email_verified
#     } for user in users]
#     return jsonify(user_data)

@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        users = User.query.all()
        user_data = []

        for user in users:
            if user.role:  # Check if user.role is not None
                user_item = {
                    'id': user.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    "phone_number": user.phone_number,
                    "has_paid": user.has_paid,
                    "referred_me": user.referred_by_id,
                    'role': user.role.role_name,  # Access role_name only if user.role is not None
                }
            else:
                # Handle the case where user.role is None (e.g., set a default role name)
                user_item = {
                    'id': user.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'role': 'Default Role',  # Set a default role name
                }

            user_data.append(user_item)

        return jsonify(user_data), 200
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while fetching users'), 500


@app.route('/users/<user_id>', methods=['GET'])
def get_user_by_id(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = user.to_dict()  # Convert User object to a dictionary

    return jsonify(user_data)


@app.route('/users/<user_id>/referrals', methods=['GET'])
def get_user_referrals(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    referral_list = user.get_referral_list()

    return jsonify(referral_list)


# @app.route('/users/<user_id>', methods=['GET'])
# def get_user_by_id(user_id):
#     try:
#         user = User.query.get(user_id)
#         if user:
#             user_data = {
#                 'id': user.id,
#                 'first_name': user.first_name,
#                 'last_name': user.last_name,
#                 'email': user.email,
#                 'profile_image': user.profile_image,
#                 "earnings": user.earnings,
#                 'role': user.role.role_name if user.role else None,
#                 'created_at': user.created_at,
#                 'modified_at': user.modified_at,
#                 "is_email_verified": user.is_email_verified,
#                 "referred_me": user.referred_me
#             }
#             return jsonify(user_data), 200
#         else:
#             return jsonify(message='User not found'), 404
#     except Exception as e:
#         print(e)
#         return jsonify(message='An error occurred while fetching the user'), 500


@app.route('/get/<referral_code>', methods=['GET'])
def check_ref_code(referral_code):
    referrer = User.query.filter_by(referral_code=referral_code).first()
    if not referrer:
        return jsonify(message='Invalid referral code provided'), 400

    return jsonify(message="Found"), 200


@app.route("/pay/", methods=["POST"])
@jwt_required()
def initialize_payment():
    # Retrieve the user from the database

    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    # Check if the user exists
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        # Generate a unique transaction reference (merchant_tx_ref)
        transaction_reference = user.id
        # verification_token = generate_verification_token(
        #     user_id, transaction_reference)

        # Prepare the data payload
        payload = {
            "data": {
                "public_key": "MSFT_live_475HC3DIJWVV7YBMJ5X6MEXT4FUU23L",
                "request_type": "live",
                "merchant_tx_ref": transaction_reference,
                # Manually construct the redirect_url with query parameters
                "redirect_url": f"https://enetworks-tovimikailu.koyeb.app/pay/{user_id}/verify",
                # "redirect_url": f"http://localhost:5000/pay/{user_id}/verify",
                "name": user.first_name,
                "email_address": user.email,
                "phone_number": user.phone_number,
                "amount": 1500,
                "currency": "NGN",
                "user_bear_charge": "no",
                "preferred_payment_option": "card",
                "description": "payment"
            }
        }

        # Make a payment request to Marasoft API to initiate payment
        response = requests.post(
            "https://checkout.marasoftpay.live/initiate_transaction",
            json=payload,
            headers={
                "Content-Type": "application/json",
            }
        )

        data = response.json()

        if response.status_code == 200 and data.get("status") == "success":
            # Update this line to access the payment URL
            payment_url = data["url"]

            # Remove the extra "?" from the redirect_url before the "status" parameter
            # redirect_url = f"http://localhost:5000/pay/{user_id}/verify"
            redirect_url = f"https://enetworks-tovimikailu.koyeb.app/pay/{user_id}/verify"
            # Update the user's payment reference in the database
            user.payment_reference = redirect_url
            db.session.commit()

            return jsonify({"payment_url": payment_url, "redirect_url": redirect_url})
        else:
            error_message = data.get("error") if data.get(
                "error") else "Payment initiation failed"
            print("Payment initiation failed:", error_message)
            return jsonify({"error": error_message}), 500

    except Exception as e:
        print("Payment initiation failed:", str(e))
        return jsonify({"error": "Payment initiation failed"}), 500


@app.route("/pay/<user_id>/verify", methods=["GET"])
def verify_payment(user_id):
    # Retrieve the query parameters from the callback URL
    status = request.args.get("status")
    transaction_reference = request.args.get("txn_ref")
    payment_reference = request.args.get("msft_ref")
    # verification_token = request.args.get("token")

    print("Received values:")
    print("Transaction Reference:", transaction_reference)
    print("Payment Reference:", payment_reference)

    # Check if the required parameters are missing
    if not status or not transaction_reference or not payment_reference:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        # Check if the payment was successful
        if status.lower() == "successful":
            # Retrieve the user from the database based on the user ID
            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "User not found"}), 404

            # Check if the payment has already been processed for this user and transaction reference
            existing_payment = SuccessfulPayment.query.filter_by(
                user_id=user_id,
                transaction_reference=transaction_reference
            ).first()

            if existing_payment:
                # Payment has already been processed, do not update earnings again
                return redirect("https://www.enetworksagencybanking.com.ng/")

            # Save the successful payment record to prevent duplicate earnings updates
            successful_payment = SuccessfulPayment(
                user_id=user_id,
                transaction_reference=transaction_reference,
                payment_amount=1500  # Change this to the actual payment amount
            )
            db.session.add(successful_payment)

            # Check if the user was referred by a mobilizer
            if user.referred_me and user.referred_me.role and user.referred_me.role.role_name == 'Mobilizer':
                referred_by_mobilizer = user.referred_me
                referred_by_mobilizer.earnings += 100  # Update mobilizer's earnings
                db.session.add(referred_by_mobilizer)

            # Check if the user's state has an executive
            if user.state:
                executives = User.query.filter_by(state=user.state).all()
                for executive in executives:
                    if executive.role and executive.role.role_name == 'Executives':
                        executive.earnings += 50
                        db.session.add(executive)

            db.session.commit()

            send_reciept_to_user(user.email, user.first_name)

            # Update the user's payment status if the payment is successful
            user.has_paid = True
            # Set the payment reference as the transaction reference
            user.payment_reference = transaction_reference
            db.session.commit()

            # Redirect to the desired URL or return a response indicating the payment was successful
            return redirect("https://www.enetworksagencybanking.com.ng/")
            # return jsonify(message="Payment Done")

        # Return a response indicating the payment was not successful
        response = {
            "paid": False,
            "user_id": user_id,
        }
        return jsonify(response), 201

    except Exception as e:
        print("Payment verification failed:", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Payment verification failed"}), 500


def get_all_admins():
    # Query the database to get all users with the 'Admin' role
    admins = User.query.join(Role).filter_by(role_name='Admin').all()

    # Convert the list of admins to dictionaries and return as JSON response
    admins_data = [{
        'id': admin.id,
        'first_name': admin.first_name,
        'last_name': admin.last_name,
        'email': admin.email,
        'role': admin.role.role_name,
    } for admin in admins]
    return jsonify(admins_data)


@app.route('/interns', methods=['GET'])
def get_all_interns():
    # Query the database to get all users with the 'Intern' role
    interns = User.query.join(Role).filter_by(role_name='Interns').all()

    # Convert the list of interns to dictionaries and return as JSON response
    intern_data = [intern.to_dict() for intern in interns]
    return jsonify(intern_data)


@app.route('/mobilizer', methods=['GET'])
def get_all_mobilizer():
    # Query the database to get all users with the 'Intern' role
    mobilizers = User.query.join(Role).filter_by(role_name='Mobilizers').all()

    # Convert the list of interns to dictionaries and return as JSON response
    mobilizer_data = [mobilizer.to_dict() for mobilizer in mobilizers]
    return jsonify(mobilizer_data)


@app.route('/executives', methods=['GET'])
def get_all_execs():
    # Query the database to get all users with the 'Intern' role
    execs = User.query.join(Role).filter_by(role_name='Executives').all()

    # Convert the list of interns to dictionaries and return as JSON response
    exec_data = [exec.to_dict() for exec in execs]
    return jsonify(exec_data)


@app.route('/upload', methods=['POST'])
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
    return jsonify({"message": "Logged out successfully"}), 200


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


def generate_enaira_id():
    unique_id = uuid.uuid4().int & (1 << 64) - 1  # Convert UUID to 64-bit integer
    return unique_id % 10**10  # Keep the last 10 digits


def generate_unique_enaira_id():
    while True:
        enaira_id = generate_enaira_id()
        existing_user = User.query.filter_by(enairaId=str(enaira_id)).first()
        if not existing_user:
            return enaira_id


def generate_account_number():
    while True:
        unique_id = uuid.uuid4().int & (1 << 64) - 1  # Convert UUID to 64-bit integer
        existing_user = User.query.filter_by(account=unique_id).first()
        if not existing_user:
            return unique_id % 10**10  # Keep the last 10 digits


@app.route('/create-executives', methods=['POST'])
def create_executives():
    valid_states = [
        'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa',
        'Benue', 'Borno', 'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti',
        'Enugu', 'FCT',  # Added FCT here
        'Gombe', 'Imo', 'Jigawa', 'Kaduna', 'Kano', 'Katsina',
        'Kebbi', 'Kogi', 'Kwara', 'Lagos', 'Nasarawa', 'Niger', 'Ogun',
        'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers', 'Sokoto', 'Taraba',
        'Yobe', 'Zamfara'
    ]

    try:
        for state in valid_states:
            email = f"enetworksEexecutive{state.replace(' ', '').capitalize()}@Enet.com"
            password = email  # Use the email as the password for simplicity
            first_name = "To Be Edited"
            last_name = "To Be Edited"
            phone_number = "To Be Edited"
            address = "To Be Edited"
            bankName = "To be Edited"

            role_name = "Executives"  # Assuming 'Executives' is the role name for executives

            # Check if the executive already exists
            existing_executive = User.query.filter_by(email=email).first()
            if not existing_executive:
                # Create a new executive user
                role = Role.query.filter_by(role_name=role_name).first()
                if role:
                    new_executive = User(
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        password=bcrypt_sha256.hash(password),
                        phone_number=phone_number,
                        role=role,
                        state=state,  # Set the state to the current state being iterated
                        address=address,
                        local_government="To Be Edited",
                        is_email_verified=True,  # Mark email as verified for simplicity
                        account=0000,
                        enairaId="0000",
                        bank_name="To be edited"
                    )

                    db.session.add(new_executive)
                    db.session.commit()

        return jsonify(message="Executives created successfully"), 201
    except Exception as e:
        db.session.rollback()
        print("Error creating executives:", str(e))
        return jsonify(message="Failed to create executives"), 500


@app.route('/executive-dashboard', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def executive_dashboard():
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if current_user.role.role_name != 'Executives':
            return jsonify(message='Access denied'), 403

        state = current_user.state

        # Get total registrations for the state
        total_registrations = User.get_total_users_per_state(state)

        # Get user details for the state (excluding the executive)
        user_details = []
        for user in User.query.filter(User.state == state, User.id != current_user_id).all():
            user_details.append({
                'address': user.address,
                'email': user.email,
                'name': user.first_name + ' ' + user.last_name,
                'phone_number': user.phone_number
            })

        # Get executive's profile details
        profile_details = {
            'name': current_user.first_name + ' ' + current_user.last_name,
            'email': current_user.email,
            'phone_number': current_user.phone_number,
            'state': current_user.state,
            'earnings': current_user.earnings
        }

        # Construct the response JSON
        response = {
            'state': state,
            'total_registrations': total_registrations,
            'profile_details': profile_details,
            'state_registrations': user_details
        }

        return jsonify(response), 200
    except Exception as e:
        print("Error fetching executive dashboard:", str(e))
        return jsonify(message="An error occurred"), 500


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
                    account=generate_account_number(),
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
@jwt_required()  # This ensures that only authenticated users (with a valid token) can access this route
@require_role(['Admin', 'Super Admin'])
def edit_user_with_id(user_id):
    try:
        current_user_id = get_jwt_identity()  # Get the ID of the authenticated user
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
        # Update other fields as needed
        if 'has_paid' in updated_data:
            user.has_paid = updated_data['has_paid']
        if 'earnings' in updated_data:
            user.earnings = updated_data['earnings']
        if 'is_email_verified' in updated_data:
            user.is_email_verified = updated_data['is_email_verified']
        if 'referrer' in updated_data:
            user.referred_by_id = updated_data['referrer']
        if 'account' in updated_data:
            user.account = updated_data['account']

        db.session.commit()

        return jsonify({'message': 'User data updated successfully'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


@app.route("/webhook/payment", methods=["POST"])
def handle_payment_webhook():
    try:
        data = request.json

        # Extract relevant fields from the webhook payload
        status = data.get("status")
        transaction_reference = data.get("txn_ref")
        payment_reference = data.get("msft_ref")
        # Add more fields as needed

        if not status or not transaction_reference or not payment_reference:
            return jsonify({"error": "Missing required parameters"}), 400

        # Retrieve the user from the database based on the payment_reference
        user = User.query.filter_by(
            payment_reference=payment_reference).first()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Check if the payment has already been processed for this user and transaction reference
        existing_payment = SuccessfulPayment.query.filter_by(
            user_id=user.id,
            transaction_reference=transaction_reference
        ).first()

        if existing_payment:
            # Payment has already been processed, do not update earnings again
            return jsonify({"message": "Payment already processed"}), 200

        # Check if the payment was successful
        if status.lower() == "successful":
            if not user.has_paid:
                # Update user's payment status and perform earnings calculations
                user.has_paid = True

                if user.referred_me and user.referred_me.role and user.referred_me.role.role_name == "Mobilizer":
                    referred_by_mobilizer = user.referred_me
                    referred_by_mobilizer.earnings += 100
                    db.session.add(referred_by_mobilizer)

                if user.state:
                    executives = User.query.filter_by(state=user.state).all()
                    for executive in executives:
                        if executive.role and executive.role.role_name == "Executives":
                            executive.earnings += 50
                            db.session.add(executive)

                db.session.commit()

                # Send receipt to user
                send_reciept_to_user(user.email, user.first_name)

            return jsonify({"message": "Payment processed successfully"}), 200
        else:
            return jsonify({"message": "Payment not successful"}), 200

    except Exception as e:
        print("Error processing payment webhook:", str(e))
        return jsonify({"error": "An error occurred while processing the webhook"}), 500


@app.route("/payments/total", methods=["GET"])
def get_total_paid_users():
    try:
        total_paid_users = User.query.filter_by(has_paid=True).count()
        return jsonify({"total_paid_users": total_paid_users}), 200
    except Exception as e:
        print("Error getting total paid users:", str(e))
        return jsonify({"error": "An error occurred while getting total paid users"}), 500


@app.route("/payments/total/interns", methods=["GET"])
def get_total_paid_interns():
    try:
        total_paid_interns = User.query.filter_by(
            has_paid=True, role_id=5).count()
        return jsonify({"total_paid_interns": total_paid_interns}), 200
    except Exception as e:
        print("Error getting total paid interns:", str(e))
        return jsonify({"error": "An error occurred while getting total paid interns"}), 500


@app.route("/payments/total/mobilizers", methods=["GET"])
def get_total_paid_mobilizers():
    try:
        total_paid_mobilizers = User.query.filter_by(
            has_paid=True, role_id=6).count()
        return jsonify({"total_paid_mobilizers": total_paid_mobilizers}), 200
    except Exception as e:
        print("Error getting total paid mobilizers:", str(e))
        return jsonify({"error": "An error occurred while getting total paid mobilizers"}), 500


if __name__ == "__main__":
    app.run(debug=True)
