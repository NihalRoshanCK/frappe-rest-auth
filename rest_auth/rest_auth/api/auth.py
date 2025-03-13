import frappe
from frappe.auth import LoginManager
from frappe.core.doctype.user.user import User

class CustomUser(User):
    def on_update(self):
        super().on_update()
        
        if not self.enabled:
            self.api_key = None
            self.api_secret = None
            self.save(ignore_permissions=True)


@frappe.whitelist(allow_guest=True)
def login(username, password, phone_id=None):
    try:
        # Authenticate the user
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(username, password)
        login_manager.post_login()

        # Generate new API Key and Secret for the user
        user = login_manager.user
        new_credentials = generate_new_api_key_and_secret(user)
        user_data=get_user_details(user)

        if not user_data.get("enabled", False):
            return "Please contact the Admin"
        
        # Check for phone_id mismatch
        if phone_id and user_data.get("phone_id") and user_data["phone_id"] != phone_id:
            frappe.response["message"] = "Phone ID mismatch"
            return "Phone ID mismatch"

        # Save the phone_id for the user if provided
        if phone_id:
            frappe.db.set_value('User', user, 'phone_id', phone_id, update_modified=False)
            frappe.db.commit()

        # Return the new credentials and user details
        frappe.response["message"] = "Logged In"
        frappe.response["key_details"] = new_credentials
        frappe.response["user_details"] = user_data

    except frappe.exceptions.AuthenticationError:
        frappe.response["message"] = "Invalid login"
        return "Invalid login"
    except KeyError as e:
        frappe.log_error(f"Missing key: {e}", "Login Error")
        frappe.response["message"] = f"KeyError: {e}"
        return f"KeyError: {e}"


def generate_new_api_key_and_secret(user):
    """Generate new API key and secret for a user."""
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
        fields=[
            "name", "first_name", "last_name", "email", "mobile_no",
            "gender", "role_profile_name", "phone_id"
        ]
    )
    return user_details[0] if user_details else {}
