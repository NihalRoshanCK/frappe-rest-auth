import frappe
from frappe import _

@frappe.whitelist(allow_guest=True)
def login(username, password):
    try:
        login_manager = frappe.auth.LoginManager()
        authenticated_user = login_manager.check_password(username, password)

        if authenticated_user:
            # Generate API Key and Secret
            api_key, api_secret = generate_keys(authenticated_user)

            # Fetch fresh data for the response
            user_doc = frappe.get_doc('User', authenticated_user)
            user_doc.reload()  # Reload to get updated data

            # Prepare success response
            frappe.response["message"] = {
                "success_key": 1,
                "message": "Authentication successful",
                "api_key": api_key,  # Use the generated api_key
                "api_secret": api_secret,  # Use the generated api_secret
                "user": authenticated_user
            }
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

    # Expire and regenerate keys
    if user_details.api_secret:
        frappe.logger().info(f"Expiring API Secret for user: {user_details.name}")
        user_details.api_secret = None

    if user_details.api_key:
        frappe.logger().info(f"Expiring API Key for user: {user_details.name}")
        user_details.api_key = None

    # Generate new keys
    api_secret = frappe.generate_hash(length=15)
    api_key = frappe.generate_hash(length=15)

    user_details.api_secret = api_secret
    user_details.api_key = api_key

    # Temporarily set user to Administrator for saving
    current_user = frappe.session.user
    frappe.set_user("Administrator")
    try:
        user_details.save()
        frappe.db.commit()  # Ensure data is written to the database
        frappe.clear_cache(user=user_details.name)  # Clear cache for user
    finally:
        frappe.set_user(current_user)

    # Debug updated values
    frappe.logger().info(f"New API Key: {user_details.api_key}, API Secret: {user_details.api_secret}")
    print(f"New API Key: {user_details.api_key}, API Secret: {user_details.api_secret}")

    # Return both API key and API secret
    return api_key, api_secret
