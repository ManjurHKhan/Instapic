from flask import Flask, Blueprint
from flask import render_template,request, redirect, jsonify
from http import cookies

mod = Blueprint("api", __name__)

@mod.route("/")
def hello():
    return "<h1 style='color:blue'>Hello WOOP World!</h1>"

@mod.route("/adduser", methods=["POST"])
def adduser():

    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@mod.route("/login", methods=["POST"])
def login():
    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@mod.route("/logout", methods=["POST"])
def logout():
    
    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@mod.route("/verify", methods=["POST"])
def verify():
    return "<h1 style='color:blue'>Hello Blah World!</h1>"
