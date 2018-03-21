from flask import Flask
from flask import render_template,request, redirect, jsonify
from http import cookies
from dbconfig import config

app = Flask(__name__)

@app.route("/")
def hello():
    return "<h1 style='color:blue'>Hello WOOP World!</h1>"

@app.route("/adduser", methods=["POST"])
def adduser():
	# # read connection parameters
 #    params = config()
 #    print(params)
 #    # connect to the PostgreSQL server
 #    print('Connecting to the PostgreSQL database...')
 #    conn = psycopg2.connect(**params)


    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@app.route("/login", methods=["POST"])
def login():
    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@app.route("/logout", methods=["POST"])
def logout():
    
    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@app.route("/verify", methods=["POST"])
def verify():
    return "<h1 style='color:blue'>Hello Blah World!</h1>"

if __name__ == "__main__":
    app.run(host='0.0.0.0')
        
