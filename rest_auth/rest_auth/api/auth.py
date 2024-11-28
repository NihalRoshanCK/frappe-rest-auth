import frappe
from frappe import _

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        login_manager = frappe.auth.LoginManager()
        authenticated_user = login_manager.check_password(username, password)

        if authenticated_user:
            api_secret = generate_keys(authenticated_user)
            user_doc = frappe.get_doc('User', authenticated_user)

            response = {
                "success_key": 1,
                "message": "Authentication successful",
                "api_key": user_doc.api_key,
                "user": authenticated_user
            }

            # Include secret only if newly generated
            if api_secret:
                response["api_secret"] = api_secret

            frappe.response["message"] = response
        else:
            frappe.response["message"] = {
                "success_key": 0,
                "message": "Invalid username or password"
            }
    except Exception as e:
        frappe.response["message"] = {
            "success_key": 0,
            "message": f"An error occurred: {str(e)}"
        }



def generate_keys(user):
    user_details = frappe.get_doc('User', user)

    # Expire and regenerate only if not present
    if not user_details.api_key:
        api_key = frappe.generate_hash(length=15)
        user_details.api_key = api_key
    else:
        api_key = user_details.api_key

    if not user_details.api_secret:
        api_secret = frappe.generate_hash(length=15)
        user_details.api_secret = api_secret
    else:
        api_secret = user_details.api_secret

    # Save changes if necessary
    current_user = frappe.session.user
    frappe.set_user("Administrator")
    try:
        user_details.save()
    finally:
        frappe.set_user(current_user)

    return api_secret


