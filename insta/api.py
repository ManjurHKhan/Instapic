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

urltoFiles = ""

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

                    query = "SELECT * FROM USERS where username=%s or email=%s;"
                    cur.execute(query, (username,email,))
                    logger.debug('adduser: fetching if username or email exists')

                    res = cur.fetchone()

                    logger.debug('adduser: fetched. %s', res)

                    if (res == None):
                        logger.debug('adduser: Starting to insert things into the table :D with %s', res)
                        query = "INSERT INTO USERS (username,password,email,salt) VALUES (%s,%s,%s,%s);";
                        
                        # Generate salt and hash the password
                        salty= base64.b64encode(os.urandom(10)).decode()[:SHA256_SALT_SIZE]
                        logger.debug(salty, "is this good? ", len(salty))

                        # Hash that password
                        secret = (pwd + salty).encode('UTF-8')
                        passwd = hashlib.sha256(secret).hexdigest()
                        # Generate validation key
                        val_key = str(uuid.uuid4()).replace("-","").upper()[0:VAL_KEY_SIZE]
                        
                        logger.debug(val_key, "is this good? ", len(val_key))

                        logger.debug(query%(username,passwd,email,salty))
                        cur.execute(query, (username,passwd,email,salty,))

                        query = "INSERT INTO VALIDATE (username,validkey) VALUES (%s,%s);"
                        cur.execute(query, (username, val_key,))
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
        query = "SELECT username FROM USERS where username=%s and validated is True;"
        cur.execute(query, (user_cookie,))
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

                    query = "SELECT salt, password, username FROM USERS where username=%s and validated is True;"
                    cur.execute(query, (username,))
                    # there should be only one  - we did all proper checks in add users, so hopefully there is only one
                    res = cur.fetchone()
                    if res != None:
                        salt = res[0]
                        secret_pass = res[1]
                        #cookie_key = res[3] # Just going to use the validation key as the cookie id
                        cookie_key = res[2] # Just going to use the username as the cookie id
                        logger.debug(salt, secret_pass,cookie_key)


                        secret = (pwd + salt).encode('UTF-8')
                        # secret = pwd + salt
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
    if (cur != None):
        cur.close()
    conn.close()
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
                query = "SELECT username FROM users where email=%s and validated is False"
                logger.debug("verify query: %s", query)
                cur.execute(query, (email,))
                rez = cur.fetchone()
                if (rez == None):
                    return jsonify(status="error", error="Invalid Verify inputs.")
                else:
                    username = rez[0]
                    logger.debug("verify: Username: %s,"%(username))
                    query = "SELECT * FROM validate where username=%s and validkey=%s;"

                    cur.execute(query, (username,key,))
                    rez = cur.fetchone()
                    if (rez == None):
                        return jsonify(status="error", error="Invalid Verify inputs.")

                    query = "UPDATE users set validated=True where username=%s and validated is False;"
                    
                    cur.execute(query, (username,))

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
    # logger.debug("current user: %s", user_cookie)
    if (user_cookie != None):
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if(data != None):
                try:
                    content = None
                    child_type = None
                    parent = None
                    media = []
                    if "content" in data:
                        content = data['content'].rstrip() if data['content'].rstrip() != "" else None # we do not need to remove starting spaces
                    if "childType" in data:
                        child_type = data['childType'].strip() if data['childType'].strip() != "" else None
                    if(child_type != None):
                        if(child_type != "retweet" and child_type != "reply"):
                            return jsonify(status="error", error="Child type does not match required child type")
                    if(content == None):
                        return jsonify(status="error", error="Content is null")
                    postid = hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()
                    
                    cur = conn.cursor()
                    parent = data["parent"].rstrip() if data["parent"].rstrip() != "" else None
                    
                    if parent != None:
                        query = "INSERT INTO posts(username, postid, content, child_type, parent_id) VALUES (%s, %s, %s, %s,%s);"
                        cur.execute(query, (user_cookie, postid, content, child_type, parent ))
                        #cur.execute(query, (user_cookie, postid, content, child_type == 'retweet', parent ))
                    else:
                        #logger.debug('additem-content 1: %s',data['content'])
                        #logger.debug('additem-content 2: %s',content)
                        query = "INSERT INTO posts(username, postid, content, child_type) VALUES (%s, %s, %s, %s);"
                        logger.debug('additem-content SQL 3: %s', query, (user_cookie, postid, content, child_type, ))
                        # logger.debug("query: %s", query % (user_cookie, postid, content, child_type == 'retweet'))
                        cur.execute(query, (user_cookie, postid, content, child_type, ))

                    if "media" in data:
                        media = data["media"]
                        print (media)
                        print (media[0])
                        # Making sure if media exists first
                        # Skipping to save time
                        for mediaid in media:
                            query = "INSERT INTO user_media (username, postid, mediaid) VALUES (%s, %s, %s);"
                            cur.execute(query, (user_cookie, postid, mediaid,))

                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK", id=postid)
                except Exception as e:
                    logger.debug('additem: something went wrong %s',e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection broke")
        conn.close()
        return jsonify(status="error", error="Data was not valid")
    conn.close()
    return jsonify(status="error", error="Not logged in")


@mod.route("/item/<id>", methods=["GET"])
def get_item(id):
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    print(user_cookie)
    if (user_cookie != None):
        try:
            logger.debug('conn:%s', conn)
            cur = conn.cursor()
            query = "SELECT username, postid, date, content,  child_type, parent_id, retweet_cnt, numliked FROM posts WHERE postid = %s;"
            logger.debug("get item query:%s", query % (str(id)))
            cur.execute(query, (str(id), ))
            i = cur.fetchone()
            if i == None:
                cur.close()
                conn.close()
                return jsonify(status="error", error = "Item not Found")
            # logger.debug("get_item - time: %s", i[2])
            # logger.debug("get_item -", (i[2].split('.')))
            # logger.debug("get_item -", (str(i[2]).split('.')))
            # logger.debug("get_item -", int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%dT%H:%M:%S'))))
            print(i)

            item = {'id':i[1], 'username':i[0], 'property':{'likes':i[7]}, 'retweeted':i[6], 'content':i[3], 'timestamp': int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%d %H:%M:%S'))), 'childType':i[4], 'parent':i[5] }
            query="SELECT mediaid from user_media where username=%s and postid=%s;";
            print (query, (user_cookie, str(id)))
            cur.execute(query, (user_cookie, str(id),) )   
            rez = cur.fetchall()
            print (query)
            print (rez)


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
    conn = None
    curr = None
    user_cookie = session.get("userID")
    logger.debug("-- search user cookie : %s", user_cookie)
    if (user_cookie != None):
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            logger.debug('search data:%s', data)

            if (data != None):
                limit = 25
                if "limit" in data:
                    limit = int(data["limit"]) if data["limit"] != None else 25
                    limit = limit if limit < 101 and limit > 0 else 25
                timestamp = time.time()
                if "timestamp" in data:
                    timestamp = int(data["timestamp"]) if data["timestamp"] != None else time.time()
                timestamp = time.ctime(timestamp)

                username = None
                q_string = None
                following = True
                q_data = (timestamp,)
                query = "SELECT * FROM posts WHERE date <= %s "
                if "username" in data:
                    username = data["username"]
                    query += "AND username = %s "
                    q_data += (username,)
                
                if "following" in data:
                    following = data["following"]
                
                if "q" in data:
                    q_string = "%%%s%%" % (data["q"])
                    query += "AND content LIKE %s "
                    q_data += (q_string,)
                
                # if "rank" in data:
                #     if data["hasMedia"].rstrip().capitalize()=="True":
                #         q_string = "%%%s%%" % (data["q"])
                #         query += "AND content LIKE %s "
                #         q_data += (q_string,)
                #  if "parent" in data:
                #     if data["parent"].rstrip() != None:
                #         q_string = "%%%s%%" % (data["q"])
                #         query += "AND content LIKE %s "
                #         q_data += (q_string,)
                #  if "replies" in data:
                #     if data["replies"].rstrip().capitalize()=="True":
                #         q_string = "%%%s%%" % (data["q"])
                # #         query += "AND childType <> "
                # #         q_data += (q_string,)

                # if "hasMedia" in data:
                #     if data["hasMedia"].rstrip().capitalize()=="True":
                #         q_string = "%%%s%%" % (data["q"])
                #         query += "AND content LIKE %s "
                #         q_data += (q_string,)
                # if username == None and not following:
                #     query += "AND username = %s "
                #     q_data += (user_cookie,)
                    
                if following:
                    query += "AND username IN (SELECT followers.follows FROM followers WHERE followers.username = %s) "
                    q_data += (user_cookie,)
                    
                query += "LIMIT %s;"
                q_data += (limit,)
                logger.debug("search query with data %s", query % (q_data))
                logger.debug("search query %s", query)

                try:
                    conn = psycopg2.connect(**params)
                    logger.debug('search conn:%s', conn)
                    cur = conn.cursor()
                    # logger.debug('search posts query:%s', query % (timestamp, limit))
                    cur.execute(query, q_data)
                    items = cur.fetchall()
                    logger.debug("search item response %s" % (items))
                    if items == None:
                        logger.debug("NONE fetch for query %s" % (query))
                        return jsonify(status="OK",  items=[])
                    ret_items = []
                    for i in items:
                        ret_items.append({'id':i[1], 'username':i[0], 'property':{'likes':i[7]}, 'retweeted':i[6], 'content':i[3], 'timestamp': int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%d %H:%M:%S')))})
                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK", items=ret_items)
                except Exception as e:
                    logger.debug('search: error  %s', e)
                    logger.debug(traceback.format_exc())
                    if (cur != None):
                        cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="error", error="Connection error while searching for items")
        conn.close()
        return jsonify(status="error", error="Data not valid")
    conn.close()
    return jsonify(status="error", error="User not logged in")

@mod.route("/item/<id>", methods=["DELETE"])
def del_item(id):
    try:
        conn = psycopg2.connect(**params)
        cur = None
        user_cookie = session.get("userID")
        # user_cookie = "dummy user"
        if (user_cookie != None):
            # we should validate the cookie here...
            
            cur = conn.cursor()
            query="DELETE FROM posts where postid = %s;"
            logger.debug("delete query %s", query % (str(id)))
            cur.execute(query, (str(id), )) 
            cur.close()
            conn.commit()
            conn.close()
        else: 
            conn.close()
            return jsonify(status="error", error="User not logged in")
    except Exception as e:
        logger.debug('users_user_is_following: error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error", error="item not deleted....")
    return jsonify(status="OK")


@mod.route("/user/<username>", methods=["GET"])
def user_info(username):
    try:
        conn = psycopg2.connect(**params)
        logger.debug('user/username conn:%s', conn)
        cur = conn.cursor()

        ret_user = {'email':None, followers:0, following:0}
        
        user_cookie = session.get("userID")
        if (user_cookie != None):
            query = "SELECT email FROM users where username = %s;"
            cur.execute(query, (username,))
            items = cur.fetchone()
            ret_user['email'] = items[0]
            
            query = "SELECT COUNT(follows) FROM followers WHERE follows = %s;"
            cur.execute(query, (username,))
            items = cur.fetchone()
            ret_user['followers'] = items[0]

            query = "SELECT count(follows) FROM followers WHERE username = %s;"
            cur.execute(query, (username,))
            items = cur.fetchone()
            ret_user['following'] = items[0]
            logger.debug("/user/%s returned %s", username, str(ret_user))
            
            cur.close()
            conn.commit()
            conn.close()
            return jsonify(status="OK", user = ret_user)

    except Exception as e:
        logger.debug('users_user_is_following: error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error", error="user not found")
    return jsonify(status="error", error="user not found")

@mod.route("/user/<username>/followers", methods=["GET"])
def user_followers(username):
    try:
        conn = psycopg2.connect(**params)
        curr = None
        user_cookie = session.get("userID")
        if (user_cookie != None):
            cur = conn.cursor()
            # check to make sure user is in the database
            query = "SELECT username FROM users where username=%s and validated is True;"
            cur.execute(query, (user_cookie,))
            rez = cur.fetchone()
            if rez == None:
                # login
                cur.close()
                conn.close()
                return jsonify(status="error", error="you are not loggged in")
            limit=50
            ### check limit params
            ll = request.args.get("limit")
            if ll != None and int(ll) <= 200 :
                limit = int(ll)
            query = "SELECT username FROM followers where follows=%s LIMIT %s;"
            cur.execute(query, (username, limit, ))
            rez = cur.fetchall()
            followers = [y for row in rez for y in row]
            print (rez)
            return jsonify(status="OK",users=followers)

    except Exception as e:
        logger.debug('users_user_is_following: error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error",error="Some DB connection failed probably")

@mod.route("/user/<username>/following", methods=["GET"])
def users_user_is_following(username):
    try:
        conn = psycopg2.connect(**params)
        curr = None
        user_cookie = session.get("userID")
        if (user_cookie != None):
            cur = conn.cursor()
            # check to make sure user is in the database
            query = "SELECT username FROM USERS where username=%s and validated is True;"
            cur.execute(query, (user_cookie,))
            rez = cur.fetchone()
            if rez == None:
                # login
                cur.close()
                conn.close()
                return jsonify(status="error", error="you are not loggged in")
            limit=50
            ### check limit params
            ll = request.args.get("limit")
            if ll != None and int(ll) <= 200 :
                limit = int(ll)
            query = "SELECT follows FROM followers where username=%s LIMIT %s;"
            logger.debug(query)
            cur.execute(query, (username, limit,))
            rez = cur.fetchall()
            followings = [y for row in rez for y in row]
            return jsonify(status="OK",users=followings)

    except Exception as e:
        logger.debug('users_user_is_following: error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error",error="Some DB connection failed probably")

@mod.route("/follow", methods=["POST"])
def user_follow():
    logger.debug('top follow: starting endpoint eval ')
    try:
        conn = psycopg2.connect(**params)
        cur = None
        user_cookie = session.get("userID")
        if (user_cookie != None):
            cur = conn.cursor()
            # check to make sure user is in the database
            query = "SELECT username FROM USERS where username=%s and validated is True;"
            cur.execute(query, (user_cookie, ))
            rez = cur.fetchone()
            if rez == None:
                # login
                cur.close()
                conn.close()
                return jsonify(status="OK")
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if (data != None):
                if "username" not in data: 
                    return jsonify(status="error", error="no username provided who are you following? ")
                username = data["username"].strip()
                follow = True
                if "follows" in data:
                    follow = data["follows"].strip().capitalize() == "True"

                # disallowing following no one, and following oneself
                if (username != None and username != user_cookie):
                    #validate the username
                    cur = conn.cursor()
                    query = "SELECT username FROM USERS where username=%s and validated is True;"
                    cur.execute(query, (username,))
                    rez = cur.fetchone()
                    if rez == None:
                        # login
                        cur.close()
                        conn.close()
                        return jsonify(status="OK")

                    if (follow):
                        #Following
                        query = "INSERT INTO followers (username, follows) VALUES(%s , %s);"
                        logger.debug("query: %s", query % (user_cookie, username))
                        cur.execute(query, (user_cookie, username,))
                        #query = "INSERT INTO following (username, following) VALUES('%s','%s') " % (username, user_cookie)
                        #cur.execute(query) 
                    else:
                        query = "DELETE FROM followers WHERE username=%s and follows=%s;"
                        cur.execute(query, (user_cookie, username,)) 
                        #query = "DELETE FROM follows WHERE username='%s' and follow='%s'"%(username, user_cookie )
                        #cur.execute(query)
                    # cur.execute(query)
                    cur.close()
                    conn.commit()
                    conn.close()
                    return jsonify(status="OK",msg="updated followers")
        return jsonify(status="error",error="Invalid request - send json please.")
        
    except Exception as e:
        logger.error('follow: Error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error",error="Some DB connection failed probably while trying to follow")

@mod.route("/item/<id>/like", methods=["POST"])
def post_like(id):
    post_id = id
    logger.debug('top follow: starting endpoint eval ')
    try:
        conn = psycopg2.connect(**params)
        cur = None
        user_cookie = session.get("userID")
        if (user_cookie != None):
            cur = conn.cursor()
            # check to make sure user is in the database
            query = "SELECT username FROM USERS where username=%s and validated is True;"
            cur.execute(query, (user_cookie, ))
            rez = cur.fetchone()
            if rez == None:
                # login
                cur.close()
                conn.close()
                return jsonify(status="OK")
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if (data != None):
                like = True
                if "like" in data: 
                    like = data["like"].strip().capitalize() == "True"
               
                if like:
                    #like
                    query = "INSERT INTO likes (username, postid) VALUES (%s , %s);"
                    cur.execute(query, (user_cookie, post_id,))
                    query = "UPDATE posts set numliked = numliked+1 where username=%s and postid=%s;"
                    #query = "UPDATE posts set numliked = (select count(*) from likes where username=%s and postid =%s);"
                    cur.execute(query, (user_cookie, post_id,))
                else: 
                    # query = "SELECT * FROM likes where username=%s and postid=%s;"
                    # cur.execute(query, (user_cookie, post_id,))
                    # rez = cur.fetchone()
                    # if rez != None and len(rez) > 0:
                    query = "DELETE FROM likes where username=%s and postid=%s RETURNING *"
                    #" and exists(select * from likes where username=%s and postid=%s );"
                    cur.execute(query, (user_cookie, post_id,))
                    #cur.execute(query, (user_cookie, post_id,user_cookie, post_id,))
                    rez = cur.fetchall()
                    if len(rez) > 0: 
                        query = "UPDATE posts set numliked = numliked-1 where username=%s and postid=%s;"
                        #query = "UPDATE posts set numliked = (select count(*) from likes where username=%s and postid =%s);"
                        cur.execute(query, (user_cookie, post_id,))
                    else:
                        # nothing was unliked
                        cur.close()
                        conn.commit()
                        conn.close()
                        return jsonify(status="error",msg="Could not unlike a post that was not liked by user in the first place")
                cur.close()
                conn.commit()
                conn.close()
                msg = "Liked a post for %s"%user_cookie if like else "Unliked a post for %s"%user_cookie
                return jsonify(status="OK",msg=msg)
        return jsonify(status="error",error="Invalid request - send json please.")
        
    except Exception as e:
        logger.error('follow: Error  %s', e)
        logger.debug(traceback.format_exc())
        return jsonify(status="error",error="Some DB connection failed probably while trying to follow")


# @mod.route("/media/<id>", methods=["GET"])
# def get_media(id):
#     domain_get_media = urltoFiles + "/%s"%(id)
#     resp = requests.request(
#         method=request.method,
#         url=request.url.replace('old-domain.com', urltoFiles),
#         headers={key: value for (key, value) in request.headers if key != 'Host'},
#         data=request.get_data(),
#         cookies=request.cookies,
#         allow_redirects=False)

#     # forward request to the file storage machine
#     pass

# @mod.route("/addmedia", methods=["POST"])
# def add_media():
#     try:
#         conn = psycopg2.connect(**params)
#         cur = None
#         user_cookie = session.get("userID")
#         if (user_cookie != None):
#             cur = conn.cursor()
#             # check to make sure user is in the database
#             query = "SELECT username FROM USERS where username=%s and validated is True;"
#             cur.execute(query, (user_cookie, ))
#             rez = cur.fetchone()
#         #forward request to the file storage machine
#         query = "INSERT INTO media (username, mediaid) VALUES (%s, %s);"
#         cur.execute(query, (user_cookie, mediaid,))
#     except Exception as e:
#         logger.error('addmedia: Error  %s', e)
#         logger.debug(traceback.format_exc())
#         return jsonify(status="error",error="Some DB connection failed probably while trying to follow")

    



                   