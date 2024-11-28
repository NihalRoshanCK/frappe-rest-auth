import frappe
from frappe.utils.password import set_encrypted_password, get_decrypted_password
from frappe import _

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        # Authenticate the user
        login_manager = frappe.auth.LoginManager()
        authenticated_user = login_manager.check_password(username, password)

        if authenticated_user:
            # Generate or regenerate API Key and Secret
            api_secret = generate_keys(authenticated_user)

            # Fetch the User document to get the API key
            user_doc = frappe.get_doc("User", authenticated_user)

            # Prepare a secure response
            frappe.response["message"] = {
                "success_key": 1,
                "message": "Authentication successful",
                "api_key": user_doc.api_key,
                "user": authenticated_user
            }
        else:
            # Invalid username or password
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
    """
    Generate or regenerate API keys and secrets for a user.
    Expire the old keys, if any, and generate new ones.
    """
    user_doc = frappe.get_doc('User', user)

    # Expire old API secret
    if user_doc.api_secret:
        frappe.logger().info(f"Expiring old API Secret for user: {user_doc.name}")
        set_encrypted_password("User", user_doc.name, None, "api_secret")

    # Generate a new API secret and encrypt it
    new_api_secret = frappe.generate_hash(length=15)
    set_encrypted_password("User", user_doc.name, new_api_secret, "api_secret")

    # Expire old API key
    if user_doc.api_key:
        frappe.logger().info(f"Expiring old API Key for user: {user_doc.name}")
        user_doc.api_key = None

    # Generate a new API key
    user_doc.api_key = frappe.generate_hash(length=15)

    # Save changes with elevated privileges
    with frappe.set_user("Administrator"):
        user_doc.save()

    # Return the new API secret for immediate use
    return new_api_secret
