import frappe
from frappe import _

@frappe.whitelist( allow_guest=True )
def login(username, password):
    try:
        login_manager = frappe.auth.LoginManager()
        login_manager.check_password(user=username, pwd=password)
    except Exception as e:
        frappe.response["message"] = {
            "success_key": 0,
            "message": f"An error occurred: {str(e)}"
        }
        return
    api_generate = generate_keys(frappe.session.user)
    user = frappe.get_doc('User', frappe.session.user)

    frappe.response["message"] = {
        "success_key":1,
        "message":"Authentication success",
        "sid":frappe.session.sid,
        "api_key":user.api_key,
        "api_secret":api_generate,
        "username":user.username,
        "email":user.email
    }


def generate_keys(user):
    user_details = frappe.get_doc('User', user)
    api_secret = frappe.generate_hash(length=15)
 
    if not user_details.api_key:
        api_key = frappe.generate_hash(length=15)
        user_details.api_key = api_key

    user_details.api_secret = api_secret
    user_details.save()

    frappe.logger().info(f"Generated API Key: {user_details.api_key}, API Secret: {api_secret}")

    return api_secret
