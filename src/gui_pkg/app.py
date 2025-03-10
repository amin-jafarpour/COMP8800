# Make other project packages visible by adding the
# parent directory of all packages to python's path.
import pathlib 
import sys
sys.path.append(str(pathlib.Path.cwd().parent))

from flask import Flask, render_template, request, jsonify

import bt_pkg.bt 



# render_template: Used to serve the markdown files. 
# request: Allows access to client request packet parameters. 
# jsonify: Allows to define an API.
# Initializes the Flask application.
app = Flask(__name__)

@app.route('/api/bluetooth/scan', methods=['GET'])
def get_bluetooth_scan():
    return bt_pkg.bt.BT.device_scan(10)



if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)