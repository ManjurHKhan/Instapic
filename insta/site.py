from flask import Blueprint

mod = Blueprint("site", ___name__)

@mod.route("/")
def ():
    return "<h1 style='color:blue'>This is the main site. </h1>"
        
