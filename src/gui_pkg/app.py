# Make other project packages visible by adding the
# parent directory of all packages to python's path.
import pathlib 
import sys
sys.path.append(str(pathlib.Path.cwd().parent))

# Import necessary modules  
from flask import Flask, render_template, request, jsonify
from bt_pkg.bt import BT
from inet_pkg.inet import Inet 





print(Inet.scan_networks)

# render_template: Used to serve the markdown files. 
# request: Allows access to client request packet parameters. 
# jsonify: Allows to define an API.
# Initializes the Flask application.
app = Flask(__name__)

@app.route('/api/bluetooth/scan', methods=['GET'])
def get_bluetooth_scan():
    return BT.device_scan(10)

@app.route('/api/inet/net/scan', methods=['GET'])
def get_inet_net_scan():
    # Inet.scan_networks(iface:str, net_count:int)
    # http://127.0.0.1:5000/api/inet/net/scan?iface=wlx000f00a3857a&net_count=5
    iface = request.args.get('iface', default='', type=str)
    net_count = request.args.get('net_count', default=1, type=int)
    net_lst = Inet.scan_networks(iface, net_count)
    return [{k: (v.decode() if isinstance(v, bytes) else v) for k, v in d.items()} for d in net_lst]




if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)