from flask import Flask, Blueprint
from flask import render_template,request, redirect, jsonify
from http import cookies
from insta.dbconfig import config

mod = Blueprint("api", __name__)

@mod.route("/")
def hello():
    return "<h1 style='color:green'>Hello Main World!</h1>"

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


@mod.route("/test_connection")
def test_pg_bouncer():
    y = test_connect()
    return y

def test_connect():
    """ Connect to the PostgreSQL database server """
    conn = None
    try:
        # read connection parameters
        params = config()
        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)
        # create a cursor
        cur = conn.cursor()
        
        # Check database version of postgresql
        cur.execute('SELECT version()')
        db_version = cur.fetchone()
        # display the PostgreSQL database server version
        print(db_version)

        # close the communication with the PostgreSQL
        cur.close()
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(params)
        print(error)
        return "TEST CONNECTION FAILED"
    finally:
        if conn is not None:
            conn.close()
            print('Database connection closed.')
            return "CONNECTION NOT CLOSED..."
        return "Success - CONNECTION CLOSED"
 
