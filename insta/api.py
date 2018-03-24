from flask import Flask, Blueprint
from flask import render_template,request, redirect, jsonify
from http import cookies
from insta.dbconfig import config
import psycopg2
import hashlib
import logging

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

SHA256_SALT_SIZE = 32
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

                    query = "SELECT * FROM USERS where username=%s or email=%s"%(username,email)
                    cur.execute(query)
                    logger.debug('adduser: fetching if username or email exists')

                    res = cur.fetchone()

                    logger.debug('adduser: fetched. %s', res)

                    if (res == None):
                        logger.debug('adduser: Starting to insert things into the table with %s', res)

                        query = "INSERT INTO USERS (username,password,email,salt) VALUES(%s,%s,%s,%s)";
                        m = hashlib.sha256()
                        psalt = os.urandom(SHA256_SALT_SIZE)
                        val_key = os.urandom(VAL_KEY_SIZE)

                        dk = hashlib.pbkdf2_hmac('sha256', pwd, psalt, 100000)
                        salty = binascii.hexlify(dk)
                        cur.execute(query%(username, pwd, email, psalt, val_key))

                        logger.debug('adduser: executed insertion of  %s, %s, %s, %s'%(username,password,email,salt))
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status=200, error="Added user - unvalidated")
                    else:
                        logger.debug('adduser: FAILED insertion of  %s, %s, %s, %s'%(username,password,email,salt))
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status=400, error="Username or email has already been taken.")

                except Exception as e:
                    logger.debug('adduser: somthing went wrong: %s',e)
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()

    logger.debug('adduser: bad json data given')
    return jsonify(status=400, error="No json data was posted")

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


def pg_connect():
    conn = None
    logger.debug('pg_connect: Starting to try to connect')

    try:
        # read connection parameters
        
        # connect to the PostgreSQL server
        logger.debug('pg_connect: before psycopg2 connect call')

        conn = psycopg2.connect(**params)
        # create a cursor
        cur = conn.cursor()
        logger.debug('pg_connect: Sreturning connection')

        return (conn,cur)
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error('pg_connect: %s', error)

        print(params)
        print(error)
        return None

def close_connect(conn, curr):
    cur.close()
    conn.commit()
    conn.close()

def test_connect():
    """ Connect to the PostgreSQL database server """
    conn = None
    try:
        # read connection parameters
        params = config()
        # connect to the PostgreSQL server
        logger.debug(params)
        
        
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
            return "Success - CONNECTION  CLOSED..."
        return "CONNECTION NOT CLOSED - conn is nulll :( "
 
