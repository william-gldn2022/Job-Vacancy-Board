from flask import Flask, render_template, Blueprint
from waitress import serve
from flask_bootstrap import Bootstrap

main = Blueprint('main', __name__)

app = Flask(__name__)

Bootstrap(app)

@main.route('/')
@main.route('/search-basic')
def basicSearch():
    return render_template('search-basic.html')

@main.route('/search-advanced')
def advancedSearch():
    return render_template('search-advanced.html')

@main.route('/user-management')
def userManagement():
    return render_template('user-management.html')

@main.route('/advert-management')
def advertManagement():
    return render_template('advert-management.html')

@main.route('/health', methods=["GET"])
def healthCheck():
    return {"Status":"Live"}, 200
