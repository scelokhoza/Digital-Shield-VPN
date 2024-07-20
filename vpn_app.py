import ssl
from flask import Flask, render_template, request, jsonify
from client.vpn_client import VPNClient
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


app = Flask(__name__)
app.secret_key = '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'

CLIENT_ID = '278547284183-63g1jifusobhdlora3k55l8e63ovsars.apps.googleusercontent.com'



vpn_client = VPNClient('config.toml')


@app.route('/google-login', methods=['POST'])
def google_login():
    token = request.json.get('id_token')
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        userid = idinfo['sub']
        return jsonify({'status': 'success', 'user_id': userid})
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 401


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