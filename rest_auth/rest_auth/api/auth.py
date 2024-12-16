import frappe
from frappe.auth import LoginManager

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        # Authenticate the user
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(username, password)
        login_manager.post_login()

        # Generate new API Key and Secret for the user
        user = login_manager.user
        new_credentials = generate_new_api_key_and_secret(user)

        # Return the new credentials and user details
        frappe.response["message"] = "Logged In"
        frappe.response["key_details"] = new_credentials
        frappe.response["user_details"] = get_user_details(user)

    except frappe.exceptions.AuthenticationError:
        frappe.response["message"] = "Invalid login"
        return False


def generate_new_api_key_and_secret(user):
    user_doc = frappe.get_doc("User", user)

    # Generate new API Key and Secret
    new_api_key = frappe.generate_hash(length=15)
    new_api_secret = frappe.generate_hash(length=15)

    user_doc.api_key = new_api_key
    user_doc.api_secret = new_api_secret
    user_doc.save(ignore_permissions=True)

    return {
        "api_key": new_api_key,
        "api_secret": new_api_secret,
    }


def invalidate_api_sessions(api_key):
    """Invalidate all sessions associated with the given API Key."""
    if not api_key:
        return

    # Remove all active sessions tied to this API Key
    frappe.db.delete("tabSession", {"api_key": api_key})
    frappe.db.commit()


def get_user_details(user):
    """Retrieve details of the user."""
    user_details = frappe.get_all(
        "User",
        filters={"name": user},
        fields=["name", "first_name", "last_name", "email", "mobile_no", "gender", "role_profile_name", "phone_id"]
    )
    return user_details if user_details else {}
