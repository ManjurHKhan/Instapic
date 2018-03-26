from flask import Flask, Blueprint
from flask import render_template,request, redirect, jsonify, make_response, session
from http import cookies
from insta.dbconfig import config, email_config
import psycopg2
import logging
import os
import binascii
import uuid
import hashlib
import base64
import time
import smtplib

## debugging tools
import traceback
# TODO we have to do something about the conn. We should really call it only inside try.
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
            username = data["username"].strip() if data["username"].strip() != "" else None
            pwd = data["password"].strip() if data["password"].strip() != "" else None
            email = data["email"].strip() if data["email"].strip() != "" else None
            logger.debug('adduser: json post things: %s, %s, %s'%(username,pwd,email))

            if (username != None and pwd != None and email != None):
                #process request
                conn = psycopg2.connect(**params)
                if(conn == None):
                    logger.debug('DB connection cannot be established for adding user. Returning error', res)
                    return jsonify(status="error", error="Database connection could not be established")
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
                        query = "INSERT INTO USERS (username,password,email,salt) VALUES ('%s','%s','%s','%s');";
                        
                        # Generate salt and hash the password
                        salty= base64.b64encode(os.urandom(10)).decode()[:SHA256_SALT_SIZE]
                        logger.debug(salty, "is this good? ", len(salty))

                        # Hash that password
                        secret = (pwd + salty).encode()
                        passwd = hashlib.sha256(secret).hexdigest()
                        # Generate validation key
                        val_key = str(uuid.uuid4()).replace("-","").upper()[0:VAL_KEY_SIZE]
                        
                        logger.debug(val_key, "is this good? ", len(val_key))

                        logger.debug(query%(username,passwd,email,salty))
                        cur.execute(query%(username,passwd,email,salty))

                        query = "INSERT INTO VALIDATE (username,validkey) VALUES ('%s','%s');";
                        cur.execute(query%(username, val_key))
                        logger.debug('adduser: executed insertion of  %s'%(username))

                        # Send validation email
                        mail = smtplib.SMTP('smtp.gmail.com',587)
                        mail.ehlo()
                        mail.starttls()
                        ouremail = "manjur.tempcse311@gmail.com"
                        passemailcode=email_config()["password"]

                        mail.login(ouremail,passemailcode)
                        content = "TO: %s\nFROM:manjur.temp311@gmail.com\nSUBJECT:Email validation code from Insta\nvalidation key: <%s>" % (email, val_key)

                        mail.sendmail(ouremail,email,content)


                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status="OK", error="Added user :D - unvalidated")
                    else:
                        logger.debug('adduser: FAILED insertion of new account: %s'%(username))
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status="error", error="Username or email has already been taken.")

                except Exception as e:
                    logger.debug('adduser: somthing went wrong: %s',e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection broke")

    logger.debug('adduser: bad json data given')
    return jsonify(status="error", error="No json data was posted")

@mod.route("/login", methods=["POST"])
def login():
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    if (user_cookie != None):
        cur = conn.cursor()
        query = "SELECT username FROM USERS where username='%s' and validated is True"%(user_cookie)
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

                    query = "SELECT salt, password, username FROM USERS where username='%s' and validated is True"%(username)
                    cur.execute(query)
                    # there should be only one  - we did all proper checks in add users, so hopefully there is only one
                    res = cur.fetchone()
                    if res != None:
                        salt = res[0]
                        secret_pass = res[1]
                        #cookie_key = res[3] # Just going to use the validation key as the cookie id
                        cookie_key = res[2] # Just going to use the username as the cookie id
                        logger.debug(salt, secret_pass,cookie_key)


                        secret = (pwd + salt).encode()
                        passwd = hashlib.sha256(secret).hexdigest()
                        logger.debug(secret,passwd)

                        if (passwd  == secret_pass):
                            #set cookie
                            resp = jsonify(status="OK")
                            session["userID"] = cookie_key
                            session["validated"] = True
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
    session.pop('validated', None)
    #resp.set_cookie('userID', expires=0)
    logger.debug('logged out')
    return jsonify(status="OK")

@mod.route("/verify", methods=["POST"])
def verify():
    logger.debug("start_verify")

    data = request.get_json(silent=True)
    if (data != None):
        key = data["key"].strip() if data["key"].strip() != "" else None
        email = data["email"].strip() if data["email"].strip() != "" else None
        if (key == None or email == None ):
            return jsonify(status="error", error="Invalid Verify inputs.")
        else:
            try:
                conn = psycopg2.connect(**params)
                curr = None
                logger.debug('conn:%s', conn)
                cur = conn.cursor()
                query = "SELECT username FROM users where email='%s' and validated is False"%(email)
                logger.debug("verify query: %s", query)
                cur.execute(query)
                rez = cur.fetchone()
                if (rez == None):
                    return jsonify(status="error", error="Invalid Verify inputs.")
                else:
                    username = rez[0]
                    logger.debug("verify: Username: %s,"%(username))
                    query = "SELECT * FROM validate where username='%s' and validkey='%s'"%(username,key)

                    cur.execute(query)
                    rez = cur.fetchone()
                    if (rez == None):
                        return jsonify(status="error", error="Invalid Verify inputs.")

                    query = "UPDATE users set validated=True where username='%s' and validated is False"%(username)
                    
                    cur.execute(query)

                    # should we delete query
                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK")
            except Exception as e:
                logger.debug('verify: somthing went wrong: %s',e)
                logger.debug(traceback.format_exc())
                if (cur != None):
                    cur.close()
                conn.commit()
                conn.close()
                return jsonify(status="error", error="Connection broke in verifying")
    return jsonify(status="error", error="No data posted. :( ")

@mod.route("/additem", methods=["POST"])
def add_items():
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    logger.debug("current user: %s", user_cookie)
    if (user_cookie != None):
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if(data != None):
                try:
                    content = data['content'].rstrip() if data['content'].rstrip() != "" else None # we do not need to remove starting spaces
                    child_type = data['childType'].strip() if data['childType'].strip() != "" else None
                    if(child_type != None):
                        if(child_type != "retweet" and child_type != "reply"):
                            return jsonify(status="error", error="Child type does not match required child type")
                    if(content == None):
                        return jsonify(status="error", error="Content is null")
                    postid = hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()
                
                    logger.debug('conn:%s', conn)
                    cur = conn.cursor()
                    query = "INSERT INTO posts(username, postid, content, retweet) VALUES ('%s', '%s', '%s', %r)"% (user_cookie, postid, content, child_type == 'retweet')
                    logger.debug("query: %s", query)
                    cur.execute(query)
                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK", id=postid)
                except Exception as e:
                    logger.debug('additem: somthing went wrong: %s',e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection broke")
        return jsonify(status="error", error="Data was not valid")
    return jsonify(status="error", error="Not logged in")


@mod.route("/item/<id>")
def get_item(id):
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    print(user_cookie)
    if (user_cookie != None):
        try:
            logger.debug('conn:%s', conn)
            cur = conn.cursor()
            query = "SELECT * FROM posts WHERE postid = '%s'" % (str(id))
            logger.debug("get item query:%s", query)
            res = cur.execute(query)
            i = res.fetchone()
            item = {'id':i[1], 'username':i[0], 'property':{'likes':i[7]}, 'retweeted':i[6], 'content':i[3], 'timestamt': int(time.mktime(time.strptime(i[2].split('.')[0], '%Y-%m-%dT%H:%M:%S')))}
            cur.close()
            conn.commit()
            conn.close()
            return jsonify(status="OK", item = item)
        except Exception as e:
            logger.debug('login: error  %s', e)
            logger.debug(traceback.format_exc())
            if (cur != None):
                cur.close()
            conn.commit()
            conn.close()
            return jsonify(status="error", error="Connection error while searching for item")
    conn.commit()
    conn.close()
    return jsonify(status="error", error="User not logged in")

@mod.route("/search", methods=["POST"])
def search():
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    if (user_cookie != None):
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if (data != None):
                limit = int(data["limit"]) if int(data["limit"]) != None else 25
                limit = limit if limit < 101 and limit > 0 else 25
                timestamp = int(data["timestamp"]) if data["limit"] != None else time.time()
                timestamp = time.ctime(timestamp)

                query = "SELECT * FROM posts WHERE data <= '%s' LIMIT %d" % (timestamp, limit)
                try:
                    logger.debug('conn:%s', conn)

                    cur = conn.cursor()
                    logger.debug('search:%s', query)
                    res = cur.execute(query)
                    items = res.fetchall()
                    ret_items = []
                    for i in items:
                        ret_items.append({'id':i[1], 'username':i[0], 'property':{'likes':i[7]}, 'retweeted':i[6], 'content':i[3], 'timestamt': int(time.mktime(time.strptime(i[2].split('.')[0], '%Y-%m-%dT%H:%M:%S')))})
                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK", items=ret_items)
                except Exception as e:
                    logger.debug('login: error  %s', e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection error while searching for items")
        conn.commit()
        conn.close()
        return jsonify(status="error", error="Data not valid")
    conn.commit()
    conn.close()
    return jsonify(status="error", error="User not logged in")





