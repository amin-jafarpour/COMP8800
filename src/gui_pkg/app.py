# Make other project packages visible by adding the
# parent directory of all packages to python's path.
import pathlib 
import sys
sys.path.append(str(pathlib.Path.cwd().parent))

# Import necessary modules  
from flask import Flask, render_template, request, jsonify
from bt_pkg.bt import BT
from inet_pkg.inet import Inet 








# render_template: Used to serve the markdown files. 
# request: Allows access to client request packet parameters. 
# jsonify: Allows to define an API.
# Initializes the Flask application.
app = Flask(__name__)

@app.route('/api/bluetooth/scan', methods=['GET'])
def get_bluetooth_scan():
    # http://127.0.0.1:5000/api/bluetooth/scan?iface=<hci#>&duration=<seconds>
    iface = request.args.get('iface', default=1, type=str)
    duration = request.args.get('duration', default=1, type=int)
    return BT.device_scan(iface, duration)

@app.route('/api/inet/net/scan', methods=['GET'])
def get_inet_net_scan():
    # http://127.0.0.1:5000/api/inet/net/scan?iface=<network-iface>&net_count=<count>&timeout=<seconds>
    iface = request.args.get('iface', default='', type=str)
    net_count = request.args.get('net_count', default=1, type=int)
    timeout = request.args.get('timeout', default=1, type=int)
    net_lst = Inet.scan_networks(iface, net_count, timeout)
    # BUG: Bytes decoding has issues. Fix it!
    # v.decode(encoding='utf-32-be', errors='ignore')
    targets = [{k: (f'{v}' if isinstance(v, bytes) else v) for k, v in d.items()} for d in net_lst]
    def clean(target):
        distance = abs(target.get('dbm_antsignal', -50))
        target['distance'] = distance
        name = target.get('info', 'b\'\'')
        if name == 'b\'\'':
            name = 'Hidden'
        else:
            name = name[2:]
            name = name[:-1]
        target['name'] = name 
       
    
    targets_fields = list(map(clean, targets))

    return render_template('radar.html', target_type='Network', targets_fields=targets)




if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)