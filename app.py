from flask import Flask, request, jsonify
import requests
import os
from datetime import datetime

app = Flask(__name__)

# Configuration for the database interaction service (mock or real)
# We use the service name defined in docker-compose.yml as the hostname within the Docker network
DB_INTERACT_SERVICE_HOST = os.environ.get('DB_INTERACT_SERVICE_HOST', 'db-interact')
# Assuming the target service (mock or real) is listening on port 5002 internally
DB_INTERACT_SERVICE_PORT = os.environ.get('DB_INTERACT_SERVICE_PORT', '5002')
# Assuming the target service has a general endpoint for logging activities
DB_INTERACT_LOG_ACTIVITY_ROUTE = os.environ.get('DB_INTERACT_LOG_ACTIVITY_ROUTE', '/log_activity')

def send_to_db_interact(activity_type, activity_data):
    """Helper function to send activity data to the database interaction service."""
    db_payload = {
        "activity_type": activity_type,
        "data": activity_data
    }
    db_interact_url = f"http://{DB_INTERACT_SERVICE_HOST}:{DB_INTERACT_SERVICE_PORT}{DB_INTERACT_LOG_ACTIVITY_ROUTE}"

    try:
        app.logger.info(f"Attempting to send {activity_type} data to db-interact service at {db_interact_url}")
        response = requests.post(db_interact_url, json=db_payload)
        app.logger.info(f"Received response from db-interact service for {activity_type}: Status Code {response.status_code}")
        return response
    except requests.exceptions.ConnectionError:
        app.logger.error(f"Connection Error: Could not connect to db-interact service at {db_interact_url}")
        raise ConnectionError(f"Could not connect to database interaction service at {db_interact_url}. Is the service running and accessible?")
    except Exception as e:
        app.logger.error(f"An unexpected error occurred sending {activity_type} data: {str(e)}")
        raise Exception(f"An unexpected error occurred: {str(e)}")


@app.route('/log/meal', methods=['POST'])
def log_meal():
    """Logs a child's meal activity."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "timestamp", "notes"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Basic validation for timestamp format (assuming ISO 8601)
    try:
        datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')) # Handle potential 'Z' for UTC
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601 (YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+HH:MM)"}), 400


    meal_data = {
        "child_id": data.get("childId"),
        "timestamp": data.get("timestamp"),
        "notes": data.get("notes")
    }

    try:
        db_response = send_to_db_interact("meal", meal_data)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"message": "Could not decode JSON response from db-interact"}

        return jsonify({"message": "Meal logged successfully", "db_response": db_response_json}), db_response.status_code
    except (ConnectionError, Exception) as e:
        return jsonify({"error": str(e)}), 500 # Use 500 for internal service errors


@app.route('/log/nap', methods=['POST'])
def log_nap():
    """Logs a child's nap activity."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "startTime", "endTime", "wokeUpDuring"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Basic validation for timestamp formats
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
        "notes": data.get("notes") # Optional field
    }

    try:
        db_response = send_to_db_interact("nap", nap_data)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"message": "Could not decode JSON response from db-interact"}
        return jsonify({"message": "Nap logged successfully", "db_response": db_response_json}), db_response.status_code
    except (ConnectionError, Exception) as e:
        return jsonify({"error": str(e)}), 500


@app.route('/log/drawing', methods=['POST'])
def log_drawing():
    """Logs a child's drawing activity."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "timestamp", "photoUrl"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Basic validation for timestamp format
    try:
        datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format. Use ISO 8601"}), 400

    # Basic validation for photoUrl (could add more robust URL validation)
    if not isinstance(data.get("photoUrl"), str) or not data.get("photoUrl").startswith("http"):
         return jsonify({"error": "Field 'photoUrl' must be a valid URL string"}), 400


    drawing_data = {
        "child_id": data.get("childId"),
        "timestamp": data.get("timestamp"),
        "title": data.get("title"), # Optional field
        "description": data.get("description"), # Optional field
        "photo_url": data.get("photoUrl")
    }

    try:
        db_response = send_to_db_interact("drawing", drawing_data)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"message": "Could not decode JSON response from db-interact"}
        return jsonify({"message": "Drawing logged successfully", "db_response": db_response_json}), db_response.status_code
    except (ConnectionError, Exception) as e:
        return jsonify({"error": str(e)}), 500


@app.route('/log/behavior', methods=['POST'])
def log_behavior():
    """Logs a child's behavioral feedback for the day."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    required_fields = ["childId", "date", "activities", "grade"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Basic validation for date format (assuming YYYY-MM-DD)
    try:
        datetime.strptime(data['date'], '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    # Basic validation for activities (must be a list of strings)
    if not isinstance(data.get("activities"), list) or not all(isinstance(item, str) for item in data.get("activities")):
        return jsonify({"error": "Field 'activities' must be a list of strings"}), 400

    # Basic validation for grade (could be an enum check in a real app)
    valid_grades = ["Excellent", "Good", "Needs Improvement"] # Example valid grades
    if data.get("grade") not in valid_grades:
         # return jsonify({"error": f"Invalid grade. Must be one of: {', '.join(valid_grades)}"}), 400 # Uncomment for strict validation
         app.logger.warning(f"Received potentially invalid grade: {data.get('grade')}") # Log warning for now


    behavior_data = {
        "child_id": data.get("childId"),
        "date": data.get("date"),
        "activities": data.get("activities"),
        "grade": data.get("grade"),
        "notes": data.get("notes") # Optional field
    }

    try:
        db_response = send_to_db_interact("behavior", behavior_data)
        try:
            db_response_json = db_response.json()
        except requests.exceptions.JSONDecodeError:
            db_response_json = {"message": "Could not decode JSON response from db-interact"}
        return jsonify({"message": "Behavior logged successfully", "db_response": db_response_json}), db_response.status_code
    except (ConnectionError, Exception) as e:
        return jsonify({"error": str(e)}), 500

# Additional endpoint suggestion: Daily Summary
# You could add an endpoint to retrieve a summary of activities for a specific child on a given day.
# This would involve making a GET request to the db-interact service.
# Example: GET /summary/<childId>/<date>

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "activity log service healthy"}), 200


if __name__ == '__main__':
    # Run the Flask app
    # Listen on all interfaces on port 5003 (arbitrary choice, will be mapped in docker-compose)
    # In production, use a production-ready WSGI server like Gunicorn or uWSGI
    app.run(host='0.0.0.0', port=5003, debug=True) # debug=True for development logging
