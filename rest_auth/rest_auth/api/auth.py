import frappe
from frappe.auth import LoginManager

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        # Authenticate the user
        login_manager = LoginManager()
        login_manager.authenticate(username, password)
        login_manager.post_login()

        # Get the user
        user = login_manager.user

        # Generate new API Key and Secret, invalidating old ones
        api_credentials = generate_new_api_key_and_secret(user)

        # Response payload
        frappe.response["message"] = "Logged In"
        frappe.response["key_details"] = api_credentials
        frappe.response["user_details"] = get_user_details(user)

    except frappe.exceptions.AuthenticationError:
        frappe.response["message"] = "Invalid login"
        return False


def generate_new_api_key_and_secret(user):
    """Generate new API Key and Secret for a user and invalidate old ones."""
    user_doc = frappe.get_doc("User", user)
    new_api_key = frappe.generate_hash(length=15)
    new_api_secret = frappe.generate_hash(length=15)

    # Set new API Key and Secret
    user_doc.api_key = new_api_key
    user_doc.api_secret = new_api_secret
    user_doc.save(ignore_permissions=True)

    # Return new credentials
    return {
        "api_key": new_api_key,
        "api_secret": new_api_secret,
    }


def get_user_details(user):
    """Fetch user details."""
    return frappe.get_all(
        "User",
        filters={"name": user},
        fields=["name", "first_name", "last_name", "email", "mobile_no", "gender", "role_profile_name"],
    )
