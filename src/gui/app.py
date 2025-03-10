from flask import Flask, render_template, request
# render_template: Used to serve the markdown files. 
# request: Allows access to client request packet parameters. 

# Initializes the Flask application.
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/file')
def index():
    return render_template('form.html')


@app.route('/submit', methods=['POST'])
def submit():
    name = request.form['name']
    return f"Hello, {name}!"



if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)

