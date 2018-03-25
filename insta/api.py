from flask import Flask, Blueprint
from flask import render_template,request, redirect, jsonify, make_response, session
from http import cookies
from insta.dbconfig import config
import psycopg2
import logging
import os
import binascii
import uuid
import hashlib
import base64

## debugging tools
import traceback

######################
### Set up Logging ###
######################
logger = logging.getLogger('instadata')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('log_api.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)
# add the handlers to logger
logger.addHandler(ch)
logger.addHandler(fh)

# Example loggers
# logger.debug('debug message')
# logger.info('info message')
# logger.warn('warn message')
# logger.error('error message')
# logger.critical('critical message')
######################

mod = Blueprint("api", __name__)


SHA256_SALT_SIZE=5
VAL_KEY_SIZE=10


params = config()


@mod.route("/")
def hello():
    return "<h1 style='color:green'>Hello Main World!</h1>"

@mod.route("/adduser", methods=["POST"])
def adduser():
    if (request.headers.get('Content-Type') == 'application/json'):
        data = request.get_json(silent=True)
        if (data != None):
            username = data["username"]
            pwd = data["password"]
            email = data["email"]
            logger.debug('adduser: json post things: %s, %s, %s'%(username,pwd,email))

            if (username != None and pwd != None and email != None):
                #process request
                conn = psycopg2.connect(**params)
                curr = None
                try:
                    ### CONNECT TO THE DATABASE
                    logger.debug('conn:%s', conn)
                    # create a cursor
                    cur = conn.cursor()
                    # validate if username or email has already been taken

                    query = "SELECT * FROM USERS where username='%s' or email='%s';"%(username,email)
                    cur.execute(query)
                    logger.debug('adduser: fetching if username or email exists')

                    res = cur.fetchone()

                    logger.debug('adduser: fetched. %s', res)

                    if (res == None):
                        logger.debug('adduser: Starting to insert things into the table :D with %s', res)

                        query = "INSERT INTO USERS (username,password,email,validation_key) VALUES('%s','%s','%s','%s','%s');";
                        # Hash that password
                        # Generate salt and hash the password

                        query = "INSERT INTO USERS (username,password,email,salt,validation_key) VALUES('%s','%s','%s','%s','%s');";
                        salty= base64.b64encode(os.urandom(10)).decode()[:SHA256_SALT_SIZE]
                        logger.debug(salty, "is this good? ", len(salty))

                        secret = (pwd + salty).encode()
                        passwd = hashlib.sha256(secret).hexdigest()
                        # Generate validation key
                        val_key = str(uuid.uuid4()).replace("-","").upper()[0:VAL_KEY_SIZE]
                        logger.debug(val_key, "is this good? ", len(val_key))

                        logger.debug(query%(username,passwd,email,salty,val_key))
                        cur.execute(query%(username,passwd,email,salty,val_key))

                        logger.debug('adduser: executed insertion of  %s'%(username))
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status=200, error="Added user :D - unvalidated")
                    else:
                        logger.debug('adduser: FAILED insertion of new account: %s'%(username))
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status=400, error="Username or email has already been taken.")

                except Exception as e:
                    logger.debug('adduser: somthing went wrong: %s',e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status=400, error="Connection broke")

    logger.debug('adduser: bad json data given')
    return jsonify(status=400, error="No json data was posted")

@mod.route("/login", methods=["POST"])
def login():
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    if (user_cookie != None):
        cur = conn.cursor()
        query = "SELECT username FROM USERS where validation_key='%s' and validated is True"%(user_cookie)
        cur.execute(query)
        rez = cur.fetchone()
        if rez != None:
            # login
            cur.close()
            conn.close()
            return jsonify(status="OK")
    if (request.headers.get('Content-Type') == 'application/json'):
        data = request.get_json(silent=True)
        if (data != None):
            username = data["username"]
            pwd = data["password"]
            logger.debug('login: json post things: %s, %s'%(username,pwd))
            if (username != None and pwd != None):
                  #process request
                
                try:
                    ### CONNECT TO THE DATABASE
                    logger.debug('conn:%s', conn)
                    # create a cursor
                    cur = conn.cursor()
                    # validate if username or email has already been taken

                    query = "SELECT salt, password, validation_key FROM USERS where username='%s' and validated is True"%(username)
                    cur.execute(query)
                    # there should be only one  - we did all proper checks in add users, so hopefully there is only one
                    res = cur.fetchone()
                    if res != None:
                        salt = res[0]
                        secret_pass = res[1]
                        cookie_key = res[2] # Just going to use the validation key as the cookie id
                        logger.debug(salt, secret_pass,cookie_key)


                        secret = (pwd + salt).encode()
                        passwd = hashlib.sha256(secret).hexdigest()
                        logger.debug(secret,passwd)

                        if (passwd  == secret_pass):
                            #set cookie
                            resp = jsonify(status="OK")
                            session["userID"] = cookie_key
                            return resp
                    else:
                        cur.close()
                        conn.close()
                        return jsonify(status="error", error="Inputted account details are not for a valid account.")
                except Exception as e:
                    logger.debug('login: error  %s',e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection broke while trying to login ")
    logger.debug('login: bad json data given')
    return jsonify(status="error", error="Insufficient json data was posted - provide a username or password")


    return "<h1 style='color:blue'>Hello Blah World!</h1>"

@mod.route("/logout", methods=["POST"])
def logout():
    #resp = make_response()
    session.pop('userID', None)
    #resp.set_cookie('userID', expires=0)
    logger.debug('logged out')
    return jsonify(status="OK")

@mod.route("/verify", methods=["POST"])
def verify():
    return "<h1 style='color:blue'>Hello Blah World!</h1>"


@mod.route("/test_connection")
def test_pg_bouncer():
    y = test_connect()
    return y





# def pg_connect():
#     conn = None
#     logger.debug('pg_connect: Starting to try to connect')

#     try:
#         # read connection parameters
        
#         # connect to the PostgreSQL server
#         logger.debug('pg_connect: before psycopg2 connect call')

#         conn = psycopg2.connect(**params)
#         # create a cursor
#         cur = conn.cursor()
#         logger.debug('pg_connect: Sreturning connection')

#         return (conn,cur)
#     except (Exception, psycopg2.DatabaseError) as error:
#         logger.error('pg_connect: %s', error)

#         print(params)
#         print(error)
#         return None

# def close_connect(conn, curr):
#     cur.close()
#     conn.commit()
#     conn.close()

# def test_connect():
#     """ Connect to the PostgreSQL database server """
#     conn = None
#     try:
#         # read connection parameters
#         params = config()
#         # connect to the PostgreSQL server
#         logger.debug(params)
        
        
#         # Check database version of postgresql
#         cur.execute('SELECT version()')
#         db_version = cur.fetchone()
#         # display the PostgreSQL database server version
#         print(db_version)

#         # close the communication with the PostgreSQL
#         cur.close()
#         conn.commit()
#     except (Exception, psycopg2.DatabaseError) as error:
#         print(params)
#         print(error)
#         return "TEST CONNECTION FAILED"
#     finally:
#         if conn is not None:
#             conn.close()
#             print('Database connection closed.')
#             return "Success - CONNECTION  CLOSED..."
#         return "CONNECTION NOT CLOSED - conn is nulll :( "



 
