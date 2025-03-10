from flask import Flask, render_template

# Initializes the Flask application.
app = Flask(__name__)

@app.route('/')
def index():
    # Serve the markdown file specified. 
    return render_template('index.html')!"




if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)

