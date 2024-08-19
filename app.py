
import os
import json
import ssl
from google.oauth2 import id_token
from google.auth.transport.requests import Request as google_Request
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from google_auth_oauthlib.flow import Flow
from client.vpn_client import VPNClient



app = Flask(__name__)
app.secret_key = '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'


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
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def google_login():
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
            return jsonify({'status': 'success', 'user_id': userid})

        except ValueError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 401

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)

    return redirect(url_for('index'))

@app.route('/start_vpn')
def start_page():
    return render_template('start_vpn.html')

@app.route('/error')
def error():
    return render_template('error.html')

@app.route('/start-vpn', methods=['POST'])
def start_vpn():
    try:
        vpn_client.connect_to_vpn()
        return jsonify({'success': True})
    except (ssl.SSLError, Exception):
        return jsonify({'success': False}), 500

@app.route('/stop-vpn', methods=['POST'])
def stop_vpn():
    try:
        # Implement logic to stop VPN
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def credentials_to_dict(credentials):
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


# Cython:

#     Cython can convert Python code into C code, which is then compiled into a binary extension. This makes it more difficult to reverse-engineer.
#     Installation:

#     bash

# pip install cython

# Usage:
# Create a setup file:

# python

# from setuptools import setup
# from Cython.Build import cythonize

# setup(
#     ext_modules = cythonize("your_script.py")
# )

# Then, build the extension:

# bash

# python setup.py build_ext --inplace

# This will produce a compiled .so or .pyd file that is much harder to reverse-engineer.
