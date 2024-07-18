import subprocess
from flask import Flask, render_template, request, jsonify
from client.vpn_client import VPNClient


app = Flask(__name__)

vpn_client = VPNClient('config.toml')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/get-started', methods=['POST'])
def vpn_page():
    return render_template('vpn.html')


@app.route('/start-vpn', methods=['POST'])
def start_vpn():
    vpn_client.connect_to_vpn()
    # return jsonify({'success': True})
    # else:
    #     return jsonify({'success': False}), 500


if __name__ == '__main__':
    app.run(debug=True)