from flask import Flask, render_template, request, jsonify
# render_template: Used to serve the markdown files. 
# request: Allows access to client request packet parameters. 
# jsonify: Allows to define an API.
# Initializes the Flask application.
app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def submit():
    name = request.form['name']
    return f"Hello, {name}!"

@app.route('/api/names', methods=['GET'])
def get_names():
    return jsonify(['Sam', 'Jason', 'James', 'Ali', 'Nicky'])



if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)

