from flask import Flask, render_template, request
from client.vpn_client import VPNClient


app = Flask(__name__)

vpn_client = VPNClient()


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/proxy', methods=['POST'])
def proxy():
    if request.method=='POST':
        url = request.form['url']
        response = vpn_client.fetch_url(url)
        return response
    

if __name__ == '__main__':
    # vpn_client.connect_to_vpn()
    app.run(debug=True)