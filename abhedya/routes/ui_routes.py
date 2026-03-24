from flask import Blueprint, render_template
ui = Blueprint('ui', __name__)

@ui.get('/')
def index():
    return render_template('index.html')

