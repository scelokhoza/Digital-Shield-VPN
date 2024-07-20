import ssl
from flask import Flask, render_template, request, jsonify
from client.vpn_client import VPNClient


app = Flask(__name__)

vpn_client = VPNClient('config.toml')


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