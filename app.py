# --- activity-log-service/app.py ---
import os
import datetime # Keep this for the datetime object itself
import jwt 
import requests
import logging
import traceback
import json # For debugging payload
from functools import wraps
from flask import Flask, request, jsonify, g
from requests.exceptions import ConnectionError, Timeout, RequestException
from dotenv import load_dotenv 

load_dotenv() 

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('ACTIVITY_LOG_SECRET_KEY', 'a_fallback_secret_for_activity_log')
DB_INTERACT_SERVICE_HOST = os.environ.get('DB_INTERACT_SERVICE_HOST', 'db-interact-svc.kindergarten-app.svc.cluster.local')
DB_INTERACT_SERVICE_PORT = os.environ.get('DB_INTERACT_SERVICE_PORT', '5000')
DB_INTERACT_LOG_ACTIVITY_ROUTE = os.environ.get('DB_INTERACT_LOG_ACTIVITY_ROUTE', '/internal/activities') # This is the endpoint on db-interact

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_jwt_secret_key_needs_change_in_env')
app.config['JWT_ALGORITHM'] = os.environ.get('JWT_ALGORITHM', 'HS256')

logging.basicConfig(level=logging.INFO) # Changed to app.logger later for consistency
# Use app.logger for Flask's built-in logger once app is created
# app.logger.info("Activity Log Service starting up...")
# app.logger.info(f"DB Interact Service Target: http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}")
# if app.config['JWT_SECRET_KEY'] == 'default_jwt_secret_key_needs_change_in_env':
#     app.logger.warning("CRITICAL: JWT_SECRET_KEY is using a default fallback. Set this in your environment!")

# --- Decorators ---
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        if not token:
            app.logger.warning("Attempt to access protected route without token.")
            return jsonify({"message": "Token is missing!"}), 401
        try:
            jwt_secret = app.config.get('JWT_SECRET_KEY')
            jwt_algo = app.config.get('JWT_ALGORITHM')
            if not jwt_secret or jwt_secret == 'default_jwt_secret_key_needs_change_in_env':
                app.logger.critical("JWT_SECRET_KEY is not configured properly!")
                return jsonify({"message": "Server configuration error regarding JWT secret"}), 500
            payload = jwt.decode(token, jwt_secret, algorithms=[jwt_algo], options={"verify_aud": False})
            if payload.get("type") != "access":
                app.logger.warning(f"Invalid token type received: {payload.get('type')}")
                return jsonify({"message": "Invalid token type provided (expected access)"}), 401
            g.current_user_id = payload.get("sub")
            g.current_user_role = payload.get("role")
            g.current_user_token = token
            if g.current_user_id is None or g.current_user_role is None:
                 app.logger.warning(f"Token payload missing 'sub' or 'role'. Payload: {payload}")
                 return jsonify({"message": "Invalid token payload"}), 401
            app.logger.info(f"Token validated for user_id: {g.current_user_id}, role: {g.current_user_role}")
        except jwt.ExpiredSignatureError:
            app.logger.warning("Expired access token presented.")
            return jsonify({"message": "Access token has expired!"}), 401
        except jwt.InvalidTokenError as e:
            app.logger.warning(f"Invalid access token received: {e}")
            return jsonify({"message": "Access token is invalid!"}), 401
        except Exception as e:
            app.logger.error(f"Unexpected error decoding token: {e}\n{traceback.format_exc()}")
            return jsonify({"message": "Error processing token"}), 500
        return f(*args, **kwargs)
    return decorated_function

# --- Service Layer (Calls to DB Interact) ---
def send_to_db_interact(activity_type, child_id_value, details_payload, user_token):
    """
    Helper function to send activity data to the database interaction service.
    The payload structure is now what db-interact's /internal/activities expects.
    """
    db_payload = {
        "child_id": child_id_value,
        "type": activity_type, # e.g., "meal", "nap", "behavior", "drawing"
        "details": details_payload 
        # 'logged_by' will be added by db-interact-service from the user_token
    }
    db_interact_url = f"http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {user_token}" 
    }

    try:
        # Ensure g.current_user_id is available or handle its absence
        user_id_for_log = getattr(g, 'current_user_id', 'UNKNOWN_USER_CONTEXT')
        app.logger.info(f"Attempting to send activity type '{activity_type}' to db-interact: {db_interact_url} for user {user_id_for_log}, child {child_id_value}")
        app.logger.debug(f"Payload to db-interact: {json.dumps(db_payload)}")
        response = requests.post(db_interact_url, json=db_payload, headers=headers, timeout=10)
        app.logger.info(f"Received response from db-interact for '{activity_type}': Status {response.status_code}, Body: {response.text[:200]}")
        return response
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection Error to db-interact at {db_interact_url}: {e}")
        raise ConnectionError(f"Could not connect to database interaction service at {db_interact_url}.")
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout connecting to db-interact at {db_interact_url}")
        raise TimeoutError(f"Request to database interaction service timed out.") # Changed to TimeoutError for consistency
    except Exception as e:
        app.logger.error(f"Unexpected error sending '{activity_type}' data to db-interact: {e}\n{traceback.format_exc()}")
        raise Exception(f"An unexpected error occurred while communicating with the database service: {str(e)}")


# --- API Routes ---

@app.route('/log/meal', methods=['POST'])
@token_required
def log_meal():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON data"}), 400
    required_fields = ["childId", "timestamp", "notes"]
    for field in required_fields:
        if field not in data: return jsonify({"error": f"Missing field: {field}"}), 400
    try:
        datetime.datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601"}), 400

    meal_details = {
        "timestamp": data.get("timestamp"),
        "notes": data.get("notes")
    }
    child_id = data.get("childId")

    try:
        db_response = send_to_db_interact("meal", child_id, meal_details, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for meal log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log meal via database service", "details": db_response_json}), db_response.status_code
        return jsonify({"message": "Meal log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e: # Added TimeoutError here
        app.logger.error(f"Error in log_meal: {e}")
        return jsonify({"error": str(e)}), 503


@app.route('/log/nap', methods=['POST'])
@token_required
def log_nap():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON data"}), 400
    required_fields = ["childId", "startTime", "endTime", "wokeUpDuring"]
    for field in required_fields:
        if field not in data: return jsonify({"error": f"Missing field: {field}"}), 400
    try:
        datetime.datetime.fromisoformat(data['startTime'].replace('Z', '+00:00'))
        datetime.datetime.fromisoformat(data['endTime'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format for startTime or endTime. Use ISO 8601"}), 400
    if not isinstance(data.get("wokeUpDuring"), bool):
         return jsonify({"error": "Field 'wokeUpDuring' must be a boolean"}), 400

    nap_details = {
        "start_time": data.get("startTime"),
        "end_time": data.get("endTime"),
        "woke_up_during": data.get("wokeUpDuring"),
        "notes": data.get("notes") 
    }
    child_id = data.get("childId")

    try:
        db_response = send_to_db_interact("nap", child_id, nap_details, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for nap log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log nap via database service", "details": db_response_json}), db_response.status_code
        return jsonify({"message": "Nap log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e: # Added TimeoutError here
        app.logger.error(f"Error in log_nap: {e}")
        return jsonify({"error": str(e)}), 503


@app.route('/log/drawing', methods=['POST'])
@token_required
def log_drawing():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON data"}), 400
    required_fields = ["childId", "timestamp", "photoUrl"]
    for field in required_fields:
        if field not in data: return jsonify({"error": f"Missing field: {field}"}), 400
    try:
        datetime.datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601"}), 400
    if not isinstance(data.get("photoUrl"), str) or not data.get("photoUrl").startswith("http"):
         return jsonify({"error": "Field 'photoUrl' must be a valid URL string"}), 400

    drawing_details = {
        "timestamp": data.get("timestamp"),
        "title": data.get("title"), 
        "description": data.get("description"), 
        "photo_url": data.get("photoUrl")
    }
    child_id = data.get("childId")

    try:
        db_response = send_to_db_interact("drawing", child_id, drawing_details, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for drawing log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log drawing via database service", "details": db_response_json}), db_response.status_code
        return jsonify({"message": "Drawing log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e: # Added TimeoutError here
        app.logger.error(f"Error in log_drawing: {e}")
        return jsonify({"error": str(e)}), 503


@app.route('/log/behavior', methods=['POST'])
@token_required
def log_behavior():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON data"}), 400
    required_fields = ["childId", "date", "activities", "grade"]
    for field in required_fields:
        if field not in data: return jsonify({"error": f"Missing field: {field}"}), 400
    try:
        datetime.datetime.strptime(data['date'], '%Y-%m-%d') 
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    if not isinstance(data.get("activities"), list) or not all(isinstance(item, str) for item in data.get("activities")):
        return jsonify({"error": "Field 'activities' must be a list of strings"}), 400

    valid_grades = ["Excellent", "Good", "Needs Improvement"] 
    if data.get("grade") not in valid_grades:
         app.logger.warning(f"Received potentially invalid grade: {data.get('grade')}") 

    behavior_details = {
        "date": data.get("date"),
        "activities": data.get("activities"),
        "grade": data.get("grade"),
        "notes": data.get("notes") 
    }
    child_id = data.get("childId")

    try:
        db_response = send_to_db_interact("behavior", child_id, behavior_details, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for behavior log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log behavior via database service", "details": db_response_json}), db_response.status_code
        
        return jsonify({"message": "Behavior log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e: # Added TimeoutError here
        app.logger.error(f"Error in log_behavior: {e}")
        return jsonify({"error": str(e)}), 503

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "activity log service healthy"}), 200


if __name__ == '__main__':
    # Configure logging for when running directly (e.g. local dev without Docker)
    # Note: When run with Gunicorn or Flask CLI, logging might be configured differently.
    if not app.debug: # Only configure if not in debug mode (Flask's reloader can cause issues)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        app.logger.addHandler(stream_handler)
    
    # Initial log messages using app.logger after it's fully available
    app.logger.info("Activity Log Service starting up (main execution block)...")
    app.logger.info(f"DB Interact Service Target: http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}")
    if app.config.get('JWT_SECRET_KEY') == 'default_jwt_secret_key_needs_change_in_env' or not app.config.get('JWT_SECRET_KEY'):
        app.logger.warning("CRITICAL: JWT_SECRET_KEY is not set or is using a default. Please set it as an environment variable for proper security.")

    app.run(host='0.0.0.0', port=5003, debug=True)
