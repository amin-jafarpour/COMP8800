from flask import Flask

# Initializes the Flask application.
app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, Flask!"


    

if __name__ == '__main__':
    # Starts the development server with debugging enabled.
    app.run(debug=True)

