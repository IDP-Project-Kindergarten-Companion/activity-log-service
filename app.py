# --- activity-log-service/app.py ---
import os
import datetime
import jwt # Make sure PyJWT is in requirements.txt
import requests
import logging
import traceback
from functools import wraps
from flask import Flask, request, jsonify, g
from requests.exceptions import ConnectionError, Timeout, RequestException
from dotenv import load_dotenv # Ensure python-dotenv is in requirements.txt

# --- Load Environment Variables ---
load_dotenv() 

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
# Service specific fallback, but ideally set via environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_fallback_secret_for_activity_log')

# Configuration for the database interaction service
DB_INTERACT_SERVICE_HOST = os.environ.get('DB_INTERACT_SERVICE_HOST', 'db-interact-svc.kindergarten-app.svc.cluster.local')
DB_INTERACT_SERVICE_PORT = os.environ.get('DB_INTERACT_SERVICE_PORT', '5000')
# Assuming db-interact-service has an endpoint like /internal/activities for logging
DB_INTERACT_LOG_ACTIVITY_ROUTE = os.environ.get('DB_INTERACT_LOG_ACTIVITY_ROUTE', '/internal/activities')

# JWT Configuration - MUST match other services
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_jwt_secret_key_needs_change_in_env')
app.config['JWT_ALGORITHM'] = os.environ.get('JWT_ALGORITHM', 'HS256')

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
app.logger.info("Activity Log Service starting up...")
app.logger.info(f"DB Interact Service Target: http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}")
if app.config['JWT_SECRET_KEY'] == 'default_jwt_secret_key_needs_change_in_env':
    app.logger.warning("CRITICAL: JWT_SECRET_KEY is using a default fallback. Set this in your environment!")


# --- Decorators ---
def token_required(f):
    """
    Decorator for Activity Log Service routes.
    Ensures a valid ACCESS JWT is present, validates it,
    and loads user info ('user_id', 'role', 'token') into Flask's 'g' object.
    This should be identical or very similar to the decorator in your other services.
    """
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

            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=[jwt_algo],
                options={"verify_aud": False} # Adjust if you use audience (aud) claim
            )

            if payload.get("type") != "access":
                app.logger.warning(f"Invalid token type received: {payload.get('type')}")
                return jsonify({"message": "Invalid token type provided (expected access)"}), 401

            g.current_user_id = payload.get("sub")
            g.current_user_role = payload.get("role")
            g.current_user_token = token # Store the raw token

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
def send_to_db_interact(activity_type, activity_data, user_token):
    """
    Helper function to send activity data to the database interaction service.
    Now includes the user_token to be passed to db-interact.
    """
    # The db-interact service will use the token to identify the 'logged_by' user
    # and for its own authorization checks if the /internal/activities endpoint is protected.
    db_payload = {
        "activity_type": activity_type, # e.g., "meal", "nap"
        "data": activity_data # Contains child_id, timestamp, details, etc.
        # 'logged_by' will be determined by db-interact-service from the user_token
    }
    db_interact_url = f"http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {user_token}" # Pass the user's token
    }

    try:
        app.logger.info(f"Attempting to send {activity_type} data to db-interact: {db_interact_url} for user {g.current_user_id}")
        response = requests.post(db_interact_url, json=db_payload, headers=headers, timeout=10)
        app.logger.info(f"Received response from db-interact for {activity_type}: Status {response.status_code}, Body: {response.text[:200]}") # Log part of body
        return response
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection Error to db-interact at {db_interact_url}: {e}")
        raise ConnectionError(f"Could not connect to database interaction service at {db_interact_url}.")
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout connecting to db-interact at {db_interact_url}")
        raise TimeoutError(f"Request to database interaction service timed out.")
    except Exception as e:
        app.logger.error(f"Unexpected error sending {activity_type} data to db-interact: {e}\n{traceback.format_exc()}")
        raise Exception(f"An unexpected error occurred while communicating with the database service: {str(e)}")


# --- API Routes ---

@app.route('/log/meal', methods=['POST'])
@token_required # Protect this endpoint
def log_meal():
    """Logs a child's meal activity."""
    # user_id and role are available in g.current_user_id, g.current_user_role
    # user_token is in g.current_user_token
    
    # Example: Only teachers can log activities (adjust as per your logic)
    # if g.current_user_role not in ['teacher', 'parent']: # Or just 'teacher'
    #     app.logger.warning(f"User {g.current_user_id} with role {g.current_user_role} attempted to log meal.")
    #     return jsonify({"error": "Forbidden: Insufficient permissions to log meal"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "timestamp", "notes"] # childId is the ID of the child
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    try:
        datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601"}), 400

    meal_data = {
        "child_id": data.get("childId"),
        "timestamp": data.get("timestamp"),
        "notes": data.get("notes")
        # 'logged_by' will be handled by db-interact based on the token
    }

    try:
        # Pass the original user's token to db-interact
        db_response = send_to_db_interact("meal", meal_data, g.current_user_token)
        
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            # If db-interact returns non-JSON (e.g., HTML error page or empty on some errors)
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 : # If it's an error status
                 app.logger.error(f"db-interact returned error for meal log: {db_response.status_code} - {db_response.text[:500]}")
                 # Return a more generic error or attempt to parse db-interact's error
                 return jsonify({"error": "Failed to log meal via database service", "details": db_response_json}), db_response.status_code


        # Forwarding the response from db-interact
        return jsonify({"message": "Meal log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code

    except (ConnectionError, TimeoutError, Exception) as e:
        app.logger.error(f"Error in log_meal while communicating with db-interact: {e}")
        return jsonify({"error": str(e)}), 503 # Service Unavailable for downstream issues


@app.route('/log/nap', methods=['POST'])
@token_required # Protect this endpoint
def log_nap():
    """Logs a child's nap activity."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "startTime", "endTime", "wokeUpDuring"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    try:
        datetime.fromisoformat(data['startTime'].replace('Z', '+00:00'))
        datetime.fromisoformat(data['endTime'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format for startTime or endTime. Use ISO 8601"}), 400

    if not isinstance(data.get("wokeUpDuring"), bool):
         return jsonify({"error": "Field 'wokeUpDuring' must be a boolean"}), 400

    nap_data = {
        "child_id": data.get("childId"),
        "start_time": data.get("startTime"),
        "end_time": data.get("endTime"),
        "woke_up_during": data.get("wokeUpDuring"),
        "notes": data.get("notes") 
    }

    try:
        db_response = send_to_db_interact("nap", nap_data, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for nap log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log nap via database service", "details": db_response_json}), db_response.status_code
        
        return jsonify({"message": "Nap log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e:
        app.logger.error(f"Error in log_nap while communicating with db-interact: {e}")
        return jsonify({"error": str(e)}), 503


@app.route('/log/drawing', methods=['POST'])
@token_required # Protect this endpoint
def log_drawing():
    """Logs a child's drawing activity."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "timestamp", "photoUrl"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    try:
        datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601"}), 400

    if not isinstance(data.get("photoUrl"), str) or not data.get("photoUrl").startswith("http"):
         return jsonify({"error": "Field 'photoUrl' must be a valid URL string"}), 400

    drawing_data = {
        "child_id": data.get("childId"),
        "timestamp": data.get("timestamp"),
        "title": data.get("title"), 
        "description": data.get("description"), 
        "photo_url": data.get("photoUrl")
    }

    try:
        db_response = send_to_db_interact("drawing", drawing_data, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for drawing log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log drawing via database service", "details": db_response_json}), db_response.status_code

        return jsonify({"message": "Drawing log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e:
        app.logger.error(f"Error in log_drawing while communicating with db-interact: {e}")
        return jsonify({"error": str(e)}), 503


@app.route('/log/behavior', methods=['POST'])
@token_required # Protect this endpoint
def log_behavior():
    """Logs a child's behavioral feedback for the day."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "date", "activities", "grade"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    try:
        datetime.datetime.strptime(data['date'], '%Y-%m-%d') # Use datetime.datetime for strptime
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    if not isinstance(data.get("activities"), list) or not all(isinstance(item, str) for item in data.get("activities")):
        return jsonify({"error": "Field 'activities' must be a list of strings"}), 400

    valid_grades = ["Excellent", "Good", "Needs Improvement"] 
    if data.get("grade") not in valid_grades:
         app.logger.warning(f"Received potentially invalid grade: {data.get('grade')}") 

    behavior_data = {
        "child_id": data.get("childId"),
        "date": data.get("date"),
        "activities": data.get("activities"),
        "grade": data.get("grade"),
        "notes": data.get("notes") 
    }

    try:
        db_response = send_to_db_interact("behavior", behavior_data, g.current_user_token)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"raw_response": db_response.text, "status_code_from_db": db_response.status_code}
            if db_response.status_code >= 400 :
                 app.logger.error(f"db-interact returned error for behavior log: {db_response.status_code} - {db_response.text[:500]}")
                 return jsonify({"error": "Failed to log behavior via database service", "details": db_response_json}), db_response.status_code
        
        return jsonify({"message": "Behavior log forwarded to database service", "db_service_response": db_response_json}), db_response.status_code
    except (ConnectionError, TimeoutError, Exception) as e:
        app.logger.error(f"Error in log_behavior while communicating with db-interact: {e}")
        return jsonify({"error": str(e)}), 503

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "activity log service healthy"}), 200


if __name__ == '__main__':
    # Ensure JWT_SECRET_KEY is set if running directly for local dev,
    # though in K8s it comes from env vars in the deployment YAML.
    if not app.config.get('JWT_SECRET_KEY') or app.config['JWT_SECRET_KEY'] == 'default_jwt_secret_key_needs_change_in_env':
        print("WARNING: JWT_SECRET_KEY is not set or is using a default. Please set it as an environment variable for proper security.")
        # For local testing without proper env setup, you might use a hardcoded one, but NEVER for production.
        # app.config['JWT_SECRET_KEY'] = 'temp-local-dev-secret' # Example for local, non-Docker run

    app.run(host='0.0.0.0', port=5003, debug=True)
