import ssl
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask import Flask, render_template, request, jsonify
from client.vpn_client import VPNClient



app = Flask(__name__)




vpn_client = VPNClient('config.toml')


@app.route('/login', methods=['POST', 'GET'])
def google_login():
    if request.method == 'POST':
        # Ensure Content-Type is application/json
        if request.content_type != 'application/json':
            return jsonify({'status': 'error', 'message': 'Unsupported Media Type'}), 415

        token = request.json.get('id_token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token not provided'}), 400

        try:
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            userid = idinfo['sub']
            return jsonify({'status': 'success', 'user_id': userid})

        except ValueError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 401

    # If method is GET, render the login page (or handle accordingly)
    return render_template('login.html')



@app.route('/')
def index():
    return render_template('index.html')


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
