# Make other project packages visible by adding the
# parent directory of all packages to python's path.
import pathlib 
import sys
sys.path.append(str(pathlib.Path.cwd().parent))

# Import necessary modules  
from flask import Flask, render_template, request, jsonify
from bt_pkg.bt import BT
from inet_pkg.inet import Inet 


# Inet.scan_networks(iface:str, net_count:int)


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
    return "heeey"




if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)