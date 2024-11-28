import frappe
from frappe import _

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        # Initialize login manager and check credentials
        login_manager = frappe.auth.LoginManager()
        authenticated_user = login_manager.check_password(username, password)
        
        if authenticated_user:

            # Generate API Key and Secret if not already present
            api_secret = generate_keys(authenticated_user)

            # Fetch the User object
            user_doc = frappe.get_doc('User', authenticated_user)

            # Prepare success response
            frappe.response["message"] = {
                "success_key": 1,
                "message": "Authentication successful",
                "api_key": user_doc.api_key,
                "api_secret": api_secret,
                "user": authenticated_user
            }
        else:
            # Handle failed login
            frappe.response["message"] = {
                "success_key": 0,
                "message": "Invalid username or password"
            }

    except Exception as e:
        # Handle unexpected errors
        frappe.response["message"] = {
            "success_key": 0,
            "message": f"An error occurred: {str(e)}"
        }


def generate_keys(user):
    user_details = frappe.get_doc('User', user)

    # Expire and regenerate the API Secret
    if user_details.api_secret:
        frappe.logger().info(f"Expiring API Secret for user: {user_details.name}")
        user_details.api_secret = None

    api_secret = frappe.generate_hash(length=15)
    user_details.api_secret = api_secret

    # Expire and regenerate the API Key
    if user_details.api_key:
        frappe.logger().info(f"Expiring API Key for user: {user_details.name}")
        user_details.api_key = None

    api_key = frappe.generate_hash(length=15)
    user_details.api_key = api_key

    # Temporarily set user to Administrator for saving
    current_user = frappe.session.user
    frappe.set_user("Administrator")
    try:
        frappe.logger().info(f"Generated API Key: {api_key} for user: {user_details.name}")
        user_details.save()
    finally:
        frappe.set_user(current_user)

    return api_secret

