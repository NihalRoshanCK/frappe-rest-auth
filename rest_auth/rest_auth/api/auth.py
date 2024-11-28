import frappe
from frappe import _

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        # Initialize the login manager
        login_manager = frappe.auth.LoginManager()
        login_manager.check_password(user=username, pwd=password)  # This raises an exception if authentication fails
        
        # Generate API Key and Secret
        api_secret = generate_keys(frappe.session.user)

        # Fetch the authenticated user's details
        user = frappe.get_doc('User', frappe.session.user)

        # Prepare success response with session ID, API keys, and user details
        frappe.response["message"] = {
            "success_key": 1,
            "message": "Authentication success",
            "sid": frappe.session.sid,  # Session ID
            "api_key": user.api_key,  # API Key
            "api_secret": api_secret,  # API Secret
            "username": user.username,  # Username
            "email": user.email  # Email
        }

    except Exception as e:
        # Handle exceptions during the login process
        frappe.response["message"] = {
            "success_key": 0,
            "message": f"An error occurred: {str(e)}"
        }

def generate_keys(user):
    # Fetch the User document
    user_details = frappe.get_doc('User', user)
    
    # Generate a new API Secret
    api_secret = frappe.generate_hash(length=15)
    
    # Check if the user already has an API Key, otherwise generate one
    if not user_details.api_key:
        api_key = frappe.generate_hash(length=15)
        user_details.api_key = api_key

    # Update the User's API Secret
    user_details.api_secret = api_secret
    user_details.save()  # Save the changes

    # Log the generated keys for debugging
    frappe.logger().info(f"Generated API Key: {user_details.api_key}, API Secret: {api_secret}")

    # Return the generated API Secret
    return api_secret
