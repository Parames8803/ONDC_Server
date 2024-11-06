from bson import ObjectId
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from datetime import timedelta
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from audioRecorder import AudioRecorder
from speechTranslator import translate_audio
import google.generativeai as genai
import threading
from google.generativeai import GenerativeModel
from PIL import Image
import os
import logging
import socket
from collections import Counter
import re
import bcrypt
import jwt
import datetime

load_dotenv()

app = Flask(__name__)
CORS(app, origins=[os.getenv("CLIENT_URL")])

# MongoDB Configuration
client = MongoClient(os.getenv("MONGO_DB_URL"))
db = client['ecart']
users_collection = db['user']
carts_collection = db['cart']

# JWT Configuration
SECRET_KEY = "mysecretkey"
app.config['JWT_SECRET_KEY'] = 'mysecretkey'  # replace with a strong secret key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

recorder = AudioRecorder()

# logging.basicConfig(level=logging.DEBUG)

# User Model
def create_user(username, email, password):
    user = {
        "username": username,
        "email": email,
        "password": hash_password(password),  # Store the hashed password
        "token": None
    }
    result = db.users.insert_one(user)
    return result.inserted_id

def find_user_by_email(email):
    return db.users.find_one({"email": email})

def update_user_token(user_id, token):
    db.users.update_one({"_id": user_id}, {"$set": {"token": token}})


# Cart Model
def get_cart_by_user_id(user_id):
    return db.carts.find_one({"userId": user_id})

def create_cart(user_id):
    cart = {"userId": user_id, "products": []}
    db.carts.insert_one(cart)
    return cart

def add_product_to_cart(user_id, product_id):
    db.carts.update_one({"userId": user_id}, {"$addToSet": {"products": product_id}})

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)
    return hashed

def check_password(password, hashed):
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def generate_token(user_id):
    token = create_access_token(identity=str(user_id))
    return token

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    

def convert_objectid_to_str(obj):
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)
    return obj


@app.route('/start_recording', methods=['GET'])
def start_recording():
    recorder.start_recording()
    return "Recording started."

@app.route('/stop_recording', methods=['GET'])
def stop_recording():
    recorder.stop_recording()
    try:
        translated_text = translate_audio('record.wav')
        return translated_text, 200
    except Exception as e:
        logging.error(f"Translation error: {e}")
        return "Translation failed.", 500


@app.route('/process_image', methods=['POST'])
def process_image():
    genai.configure(api_key="AIzaSyBxqos-ABArpNayKu-h5r06BqZdDwUR0F4")
    logging.debug("Received request to /process_image")

    # Ensure a file is sent with the request
    if 'image' not in request.files:
        logging.error("No file part in the request")
        return "No file part", 400

    file = request.files['image']

    if file.filename == '':
        logging.error("No selected file")
        return "No selected file", 400

    # Save the uploaded image temporarily
    temp_image_path = 'temp_uploaded_image.jpeg'
    file.save(temp_image_path)
    logging.debug("File saved successfully")

    # Open and process the image
    try:
        img = Image.open(temp_image_path)
        logging.debug("Successfully opened image")
    except Exception as e:
        logging.error(f"Error opening image: {str(e)}")
        return f"Error opening image: {str(e)}", 400

    # Initialize the generative model
    model = GenerativeModel(model_name="gemini-1.5-flash")
    try:
        response = model.generate_content(["What is in this image?", img])
        logging.debug("Successfully generated content from image")
    except Exception as e:
        logging.error(f"Error generating content: {str(e)}")
        return f"Error generating content: {str(e)}", 500

    # Extract description and primary keyword
    description = response.text
    words = re.findall(r'\b\w+\b', description.lower())
    common_words = Counter(words).most_common()
    keyword = next((word for word, count in common_words if word not in ["the", "a", "on", "of", "image","was","it", "this", "and", "are", "with", "is", "some"]), None)
    
    print(keyword)
    return jsonify({"primary_keyword": keyword or "No primary keyword detected"})



@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    if data.get('isLogin'):
        # Login functionality
        user = find_user_by_email(data['email'])
        if not user or not check_password(data['password'], user['password']):
            return jsonify({"message": "Invalid credentials"}), 401

        # Generate token
        token = generate_token(user['_id'])
        update_user_token(user['_id'], token)
        return jsonify({"token": token, "username": user['username']}), 200

    else:
        # Register functionality
        if find_user_by_email(data['email']):
            return jsonify({"message": "User already exists"}), 409
        user_id = create_user(data['username'], data['email'], data['password'])
        token = generate_token(user_id)
        update_user_token(user_id, token)
        return jsonify({"token": token, "username": data['username']}), 201

# Cart functionality
@app.route('/user/cart', methods=['POST'])
@jwt_required()
def manage_cart():
    product_id = request.json.get("id")
    current_user = get_jwt_identity() 
    print({current_user})

    cart = get_cart_by_user_id(current_user)
    if not cart:
        create_cart(current_user)

    add_product_to_cart(current_user, product_id)
    return jsonify({"message": "Product added to cart"}), 200

@app.route('/user/cart/details', methods=['GET'])
@jwt_required()
def get_cart():
    current_user = get_jwt_identity()
    print({current_user})
    cart = get_cart_by_user_id(current_user)
    print(cart)
    
    if not cart:
        return jsonify({"message": "No Products Found"}), 404
    
    # Convert ObjectId to string using utility function
    cart = convert_objectid_to_str(cart)

    return jsonify(cart), 200


# Delete product from cart
@app.route('/user/cart/<string:product_id>', methods=['DELETE'])
@jwt_required()
def delete_cart(product_id):
    current_user = get_jwt_identity()
    print({id: product_id})
    print({current_user})
    cart = get_cart_by_user_id(current_user)
    
    if not cart:
        return jsonify({"message": "Cart not found"}), 404
    
    # Remove the product from the cart
    cart["products"] = [product for product in cart["products"] if product != product_id]
    db.carts.update_one({"userId": current_user}, {"$set": {"products": cart["products"]}})
    
    return jsonify({"message": "Product removed from cart successfully"}), 200


if __name__ == '__main__':
    try:
        app.run(debug=True, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
    except Exception as e:
        print(f"Error starting the Flask app: {e}")
