import os
import ssl
import json
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as google_Request
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from client.vpn_client import VPNClient



app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


with open("client_secret.json") as f:
    config = json.load(f)

CLIENT_ID = config["web"]["client_id"]


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Use only for testing, disable in production


flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.profile"],
    redirect_uri="http://127.0.0.1:5000/callback"
    )


vpn_client = VPNClient('config.toml')



@app.route('/')
def index():
    """
    Defines the root route of the application, rendering the index.html template.

    Returns:
        The rendered index.html template.
    """
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def google_login():
    """
    Handles Google login requests.

    This function handles both POST and GET requests to the /login route.
    For POST requests, it verifies the provided ID token and returns the user's ID if successful.
    For GET requests, it redirects the user to the Google authorization URL.

    Returns:
        A JSON response with the user's ID if the login is successful, or an error message otherwise.
    """
    if request.method == 'POST':
        if request.content_type != 'application/json':
            return jsonify({'status': 'error', 'message': 'Unsupported Media Type'}), 415

        token = request.json.get('id_token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token not provided'}), 400

        try:
            idinfo = id_token.verify_oauth2_token(token, google_Request(), CLIENT_ID)

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            userid = idinfo['sub']
            session['user_id'] = userid
            session['user_name'] = idinfo['name']
            session['user_picture'] = idinfo['picture']
            return jsonify({'status': 'success', 'user_id': userid})

        except ValueError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 401

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """
    Handles the OAuth callback from Google.

    This function is called when the user is redirected back to the application
    after authorizing access. It fetches the authorization token, extracts the
    credentials, and stores them in the session.

    Returns:
        A redirect to the index page.
    """
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)

    return redirect(url_for('start_page'))

@app.route('/start_vpn')
def start_page():
    """
    Route decorator for the '/start_vpn' endpoint.

    This function is responsible for rendering the 'start_vpn.html' template.

    Returns:
        The rendered HTML template.
    """
    return render_template('start_vpn.html')

@app.route('/error')
def error():
    """
    Route decorator for the '/error' endpoint.

    This function is responsible for rendering the 'error.html' template.

    Returns:
        The rendered HTML template for the error page.
    """
    return render_template('error.html')

@app.route('/start-vpn', methods=['POST'])
def start_vpn():
    """
    Route decorator for the '/start-vpn' endpoint with POST method.

    This function is responsible for starting the VPN connection. It attempts to
    establish a secure connection to the VPN server by calling the `connect_to_vpn`
    method of the `vpn_client` object. If the connection is successful, it returns
    a JSON response with a success status of `True`. If an SSL error or any other
    exception occurs during the connection process, it returns a JSON response
    with a success status of `False` and a 500 HTTP status code.

    Returns:
        A JSON response with a success status and an HTTP status code.

    Raises:
        None.
    """
    try:
        vpn_client.connect_to_vpn()
        return jsonify({'success': True})
    except (ssl.SSLError, Exception):
        return jsonify({'success': False}), 500

@app.route('/stop-vpn', methods=['POST'])
def stop_vpn():
    """
    Route decorator for the '/stop-vpn' endpoint with POST method.

    This function is responsible for stopping the VPN connection. It attempts to
    disconnect from the VPN server by calling the `disconnect_from_vpn` method of
    the `vpn_client` object. If the disconnection is successful, it returns a JSON
    response with a success status of `True`. If an exception occurs during the
    disconnection process, it returns a JSON response with a success status of
    `False`, an error message, and a 500 HTTP status code.

    Returns:
        A JSON response with a success status, an optional error message, and an
        HTTP status code.
    """
    try:
        vpn_client.disconnect_from_vpn()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def credentials_to_dict(credentials):
    """
    Convert the given `credentials` object to a dictionary representation.

    Args:
        credentials (google.oauth2.credentials.Credentials): The credentials object to convert.

    Returns:
        dict: A dictionary containing the following keys:
            - "token" (str): The access token.
            - "refresh_token" (str): The refresh token.
            - "token_uri" (str): The token URI.
            - "client_id" (str): The client ID.
            - "client_secret" (str): The client secret.
            - "scopes" (List[str]): The list of scopes.
    """
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }


if __name__ == '__main__':
    app.run(debug=True)






