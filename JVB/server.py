from flask import Flask, render_template
from waitress import serve
from flask_bootstrap import Bootstrap

app = Flask(__name__)

Bootstrap(app)

@app.route('/')
@app.route('/search-basic')
def basicSearch():
    return render_template('search-basic.html')

@app.route('/search-advanced')
def advancedSearch():
    return render_template('search-advanced.html')

@app.route('/user-management')
def userManagement():
    return render_template('user-management.html')

@app.route('/advert-management')
def advertManagement():
    return render_template('advert-management.html')

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=5000)
