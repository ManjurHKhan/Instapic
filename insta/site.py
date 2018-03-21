from flask import Blueprint

mod = Blueprint("site", __name__)

@mod.route("/")
def main_front():
    return "<h1 style='color:blue'>This is the main site. </h1>"
        
