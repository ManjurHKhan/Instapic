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
import requests

from elasticsearch import Elasticsearch


import _thread
from threading import Thread
import urllib.request as urllib
from urllib.parse import urlencode
## debugging tools
import traceback

urltoFiles = ""

es = Elasticsearch([{'host': '130.245.171.41', 'port': 9200}])
INDEX_NAME = "insta_index"

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

mod = Blueprint("app", __name__)

app = Flask(__name__)

app.secret_key = 'prsW3dojaskl12=121341x3'



SHA256_SALT_SIZE=5
VAL_KEY_SIZE=10

params = config()

### Setting up Elastic search configs here - resetting a of elastic search
request_body = {
    "settings" : {
        "number_of_shards": 1,
        "number_of_replicas": 0
    }
}
if es.indices.exists(INDEX_NAME):
    print("deleting '%s' index..." % (INDEX_NAME))
    res = es.indices.delete(index = INDEX_NAME)
    es.indices.create(index = INDEX_NAME, body = request_body)

else:
    es.indices.create(index = INDEX_NAME, body = request_body)



# this is threaded email - sends email through node email server
def send_email(email, val_key):
    logger.debug('THREAD - STARTING TO SEND EMAIL to: %s', email)
    url = "http://130.245.171.38/email?%s" % (urlencode({'to':email, 'text':val_key}))
    f = urllib.urlopen(url)
    return f.getcode() == 200 # return true if email was sent successfully


def send_delete_node(postid):
    logger.debug('THREAD - STARTING TO delete post %s', postid)
    url = "http://130.245.171.38/delete/%s" % (postid)
    f = urllib.urlopen(url)
    return f.getcode() == 200 # return true if deleted node


# def send_add_item(postid, data):
#     logger.debug('THREAD - STARTING TO delete post %s', postid)
#     url = "http://130.245.171.38/additem/%s" % (postid)
#     r = requests.post(url)
#     return f.getcode() == 200 # return true if deleted node

def add_item_thread(user_cookie, postid, data):
    logger.debug('THREAD - STARTING TO add post %s', postid)

    headers = {'Content-Type': 'application/json'}

   
    data["postid"] = postid
    data["user_cookie"] = user_cookie
    url = "http://130.245.171.38/additem"
    #r = requests.post(url,  data={'number': 12524, 'type': 'issue', 'action': 'show'}, headers=headers)
    r = requests.post(url,  json={'data': data}, headers=headers)
    # data["postid"] = postid
    # url = "http://130.245.168.64/additem"
    # #r = requests.post(url, data = data)
    # req = urllib.Request(url, data)
    logger.debug('DONE LD %s', postid)
    # console.log('DONE LD %s', postid)

    return True # return true -- assume always good
    
def t_insert_ES(postid, data):
    es.index(index=INDEX_NAME,doc_type='posts',id=postid,body=data)

#mail = smtplib.SMTP('localhost')
@mod.route("/")
def hello():
    return "<h1 style='color:green'>Hello Main World!</h1>"

@mod.route("/test", methods=["POST"])
def hello1():
    node = request.get_json(silent=True)
    print("ADDING", node)

    x = es.index(index=INDEX_NAME,doc_type='external',body=node)
    print (x)
    logger.debug(x)
    return jsonify(data=x)


@mod.route("/addpostnode", methods=["POST"])
def ADD_post_node():
    node = request.get_json(silent=True)
    print("ADDING", node)

    x = es.index(index=INDEX_NAME,doc_type='posts',body=node)
    print (x)
    logger.debug(x)
    return jsonify(data=x)


@mod.route("/test2")
def hello2():
    esbody = {
                        "query": {
                            "bool": {
                                "must": [
                                {  "match": { "content": "KWdeemglJxiHVrVc" }}
                                #,
                                # { "range": { "timestamp":  {
                                #             "gte" : timestamp,
                                #             }
                                #             } KWdeemglJxiHVrV
                                #             }
                                ] 

                                # }
                               }
                            }
                        }
    print (esbody)
    rez = es.search(index=INDEX_NAME,doc_type='posts', body=esbody);
    print(rez)
    hits = rez["hits"]
    logger.debug(rez)
    return jsonify(data=rez, hits=hits)


@mod.route("/test_index")
def hello_in():
    rez = es.search(index=INDEX_NAME,doc_type='posts',terminate_after=20, body={
                                                                "query": { 
                                                                    "match_all" : 
                                                                        {  }
                                                                    }
    #                                                             }
    #                                                              "query": {

    #                 "bool": {
    #                     "must": [
    #                               {  "regexp": { "content": ".*so.*" }},
    #                               { "match": { "key": "4950D6B339" }} ] 
                        
    #                 }
    # }
       });
    print(rez)
    hits = rez["hits"]
    return jsonify(data=rez, hits=hits)
    #return "<h1 style='color:green'>Hello Main World!</h1>"


@mod.route("/clear")
def hello_clear():
    if es.indices.exists(INDEX_NAME):
        print("deleting '%s' index..." % (INDEX_NAME))
        res = es.indices.delete(index = INDEX_NAME)
    es.indices.create(index = INDEX_NAME, body = request_body)
    es.index(index=INDEX_NAME,doc_type='external',id=_id,body=node)
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

                        # Hash that password
                        secret = (pwd + salty).encode('UTF-8')
                        passwd = hashlib.sha256(secret).hexdigest()
                        # Generate validation key
                        try:
                            val_key = str(uuid.uuid4()).replace("-","").upper()[0:VAL_KEY_SIZE]
                            logger.debug("executing query in add user")

                            logger.debug(query%(username,passwd,email,salty))
                            cur.execute(query, (username,passwd,email,salty,))

                            query = "INSERT INTO VALIDATE (username,validkey) VALUES (%s,%s);"
                            cur.execute(query, (username, val_key,))
                            logger.debug('adduser: executed insertion of  %s'%(username))
                            
                            logger.debug('starting validation email  %s'%(username))
                            if not send_email(email, val_key): raise Exception("Email was not sent properly")
                        except Exception as e:
                            logger.debug('adduser: somthing went wrong early: %s',e)
                            logger.debug(traceback.format_exc())

                            return jsonify(status="error", error="Username or email has already been taken. Or email was not sent")

                        # Send validation email via thread
                        #try:
                        #    _thread.start_new_thread(send_email, (email, val_key, ) )
                        #except Exception as e:
                        #    logger.debug('Error on thread for email: %s', e)
                        #    logger.debug(traceback.format_exc())

                        logger.debug('adduser: After mail is sent to username %s'%(username))

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
                            if cur != None:
                                cur.close()
                            if conn != None:
                                conn.close()

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
                    if conn != None:
                        conn.commit()
                        conn.close()
                    return jsonify(status="error", error="Connection broke while trying to login ")
    if (cur != None):
        cur.close()
    if conn != None:
        conn.close()
    # logger.debug('login: bad json data given')
    return jsonify(status="error", error="Insufficient json data was posted - provide a username or password")


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
                    if cur != None:
                        cur.close()
                    if conn != None:
                        conn.close()

                    return jsonify(status="error", error="Invalid Verify inputs.")
                else:
                    username = rez[0]
                    logger.debug("verify: Username: %s,"%(username))
                    query = "SELECT * FROM validate where username=%s and validkey=%s;"

                    cur.execute(query, (username,key,))
                    rez = cur.fetchone()
                    if (rez == None):
                        if cur != None:
                            cur.close()
                        if conn != None:
                            conn.close()
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
    

    # req = urllib.Request(url, data)
    #   urllib(url, {
    #     method: 'POST',
    #     headers: {
    #   'Content-Type': 'application/json'
    # },
    #     data: data
    #   });

    user_cookie = session.get("userID")
    if (user_cookie != None):
        if (request.headers.get('Content-Type') == 'application/json'):
            data = request.get_json(silent=True)
            if(data != None):
                try:
                    child_type = None
                    content = None
                    if "content" in data:
                        content = data['content'].rstrip() if data['content'].rstrip() != "" else None # we do not need to remove starting spaces
                    if "childType" in data:
                        child_type = data['childType'].strip() if data['childType'].strip() != "" else None
                    if(child_type != None):
                        if(child_type != "retweet" and child_type != "reply"):
                            return jsonify(status="error", error="Child type does not match required child type")
                    if(content == None):
                        return jsonify(status="error", error="Content is null")
                    
                    parent = None
                    if "parent" in data:
                        parent = data["parent"].rstrip() if data["parent"].rstrip() != "" else None
                    
                    if parent == None and child_type != None:
                        return jsonify(status="error", msg="You cant be a child if you dont have a parent.")

                    postid = hashlib.md5((str(time.time()) + user_cookie).encode('utf-8')).hexdigest()

                    #insert to elastic search
                    data["postid"] = postid
                    _thread.start_new_thread(add_item_thread,(user_cookie, postid, data,))
                    # send to node for now
                    #_thread.start_new_thread(add_item_thread, (user_cookie, postid, data,))
                    return jsonify(status="OK", id=postid)
                except Exception as e:
                    logger.debug(e)
                    logger.debug(traceback.format_exc())
                    return jsonify(status="error", error="Connection broke")
        
        return jsonify(status="error", error="Data was not valid")

    return jsonify(status="error", error="Not logged in")


@mod.route("/item/<id>", methods=["GET"])
def get_item(id):
    conn = psycopg2.connect(**params)
    curr = None
    user_cookie = session.get("userID")
    if (user_cookie != None):
        try:
            logger.debug('conn:%s', conn)
            cur = conn.cursor()
            query = "SELECT posts.username, posts.postid, date, content, child_type, parent_id, retweet_cnt, numliked, user_media.mediaid FROM posts FULL OUTER JOIN user_media ON posts.postid = user_media.postid WHERE posts.postid = %s;"
            logger.debug("get item query:%s", query % (str(id)))
            cur.execute(query, (str(id), ))
            items = cur.fetchall()
            media = []
            if len(items) == 0:
                if cur != None:
                    cur.close()
                if conn != None:
                    conn.close()
                return jsonify(status="error", error = "Item not Found")
           
            for it in items: 
                if it[8] != None:
                    media.append(it[8])
            i = items[0]    
            item = {'id':i[1], 
                    'username':i[0], 
                    'property':
                        {
                            'likes':i[7]
                        }, 
                    'retweeted':i[6],
                    'content':i[3],
                    'timestamp': int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%d %H:%M:%S'))), 
                    'childType':i[4], 
                    'parent':i[5], 
                    'media':media
                 }
            # query="SELECT mediaid from user_media where username=%s and postid=%s;";
            # cur.execute(query, (user_cookie, str(id),) )   
            # rez = cur.fetchall()
            cur.close()
            conn.commit()
            conn.close()
            return jsonify(status="OK", item = item)
        except Exception as e:
            if cur != None:
                cur.close()
            if conn != None:
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

            dic = {

            "interest": {  "time" : {"order" : "asc"}},
            "rank": {  "sume(likes+ retweets) " : {"order" : "asc"}},
            "parent" : {"match"},
            "hasMedia" : {"true"},

            }


            try:
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

                    


                    #select * from posts FULL OUTER JOIN user_media on posts.postid = user_media.postid;
                    #posts.username, posts.postid, date, content, child_type, parent_id, retweet_cnt, numliked, user_media.mediaid
                    #query = "SELECT * FROM posts FULL OUTER JOIN user_media WHERE date <= %s ORDER BY posts.postid"
                    query = "SELECT posts.username, posts.postid, date, content, child_type, parent_id, retweet_cnt, numliked, user_media.mediaid FROM (%s) as posts "
                    
                    joinquery = "%s user_media on posts.postid = user_media.postid "
                    secretjoin = "FULL OUTER JOIN"
                    miniquery = "SELECT username, postid, date, content, child_type, parent_id, retweet_cnt, numliked, COALESCE(posts.retweet_cnt) + COALESCE(posts.numliked) as sum from posts "
                    logger.warn("checking has media")
                    
                    if "hasMedia" in data:
                        hasMedia = data["hasMedia"].rstrip().capitalize() == "True"
                        if hasMedia:
                            joinquery = joinquery %("INNER JOIN") 
                            secretjoin = "INNER JOIN"
                            miniquery = "SELECT DISTINCT(posts.*), COALESCE(posts.retweet_cnt) + COALESCE(posts.numliked) as sum FROM posts %s user_media on posts.postid = user_media.postid "%secretjoin
                        else:
                            joinquery = joinquery %("FULL OUTER JOIN")
                    else:
                        joinquery = joinquery %("FULL OUTER JOIN")

                    logger.warn("minquery")
                    
                    miniquery += "WHERE date <= %s "

          
                    if "username" in data:
                        username = data["username"]
                        miniquery += "AND posts.username = %s "
                        q_data += (username,)
                    
                    if "following" in data:
                        following = data["following"]
                
                    where_query = ""
                    if "q" in data:
                        
                        #q_string = "%%%s%%" % (data["q"])
                        #miniquery += "AND content LIKE %s "
                        

                        # q_data += (q_string,)
                        # q_data = (" ",)
                        es_body = {
                        "query": {
                            "bool": {
                                "must": [
                                {  "match": { "content": "%s"%(data["q"].replace("\n",""))} }
                                #,
                                # { "range": { "timestamp":  {
                                #             "gte" : timestamp,
                                #             }
                                #             } KWdeemglJxiHVrV
                                #             }
                                ] 

                                # }
                               }
                            }
                        }
                        logger.warn(es_body)
                        logger.warn("starting elastic search searching for %s here"% limit)
                                
                        rez = es.search(index=INDEX_NAME,doc_type='posts',terminate_after=limit, body=es_body)
                        hits = rez["hits"]["hits"]
                        hit_ids = ["'"+x["_id"]+"'" for x in hits]
                        print (es_body, hit_ids)
                        # print(rez, "SOOOOOOO");
                        # print(hits);

                        if len(hit_ids)> 0:
                            str_hits = "(%s)" %( ",".join(hit_ids) )
                            # where_query = " WHERE posts.postid in " + str_hits + " "
                            miniquery += " AND  posts.postid in " + str_hits + " "
                        else:
                            return jsonify(status="OK", items=[])
                    rank_order = ""
                    if "rank" in data:
                        rank = data["rank"].rstrip()
                        if rank == "time":
                            rank_order = "posts.date DESC"

                        elif rank == "interest":
                            rank_order = "sum DESC"
                            #rank_order = "COALESCE(posts.retweet_cnt) + COALESCE(posts.numliked) DESC"
                        else:
                            if cur != None:
                                cur.close()
                            if conn != None:
                                conn.close()
                            return jsonify(status="error", error="invalid Rank type passed in")
                    else:
                        rank_order = "sum DESC"

                        #rank_order = "COALESCE(posts.retweet_cnt) + COALESCE(posts.numliked) DESC"

                    if "parent" in data:
                        if data["parent"].rstrip() != None:
                            parent = data["parent"]
                            miniquery += "AND parent_id = %s "
                            q_data += (parent,)
                    if "replies" in data:
                        if data["replies"].rstrip().capitalize()=="False":
                            
                            miniquery += "AND (child_type != %s  OR child_type is NULL) "
                            q_data += ("reply",)
                   

                    # if "hasMedia" in data:
                    #     if data["hasMedia"].rstrip().capitalize()=="True":
                    #         q_string = "%%%s%%" % (data["q"])
                    #         query += "AND content LIKE %s "
                    #         q_data += (q_string,)
                    # if username == None and not following:
                    #     query += "AND username = %s "
                    #     q_data += (user_cookie,)
                        
                    if following:
                        miniquery += "AND posts.username IN (SELECT followers.follows FROM followers WHERE followers.username = %s)  "
                        q_data += (user_cookie,)
                   
                     
                    order_query = "ORDER BY " + rank_order  + ", posts.postid"

                    miniquery += order_query

                    miniquery += " LIMIT %s"
                    q_data += (limit,)
                    logger.warn( "hello")
                    logger.warn( q_data)

                    query = query % miniquery + joinquery + where_query+ order_query
                    logger.debug('search data:\n%s', query)
                    logger.debug('search data: %s', query)

                    # print (query)
                    # print (q_data)
                    # logger.debug("search query with data %s", query % (q_data))

                    logger.debug("search query %s", query)
                    # print (q_data)
                    # print (query %(q_data))

                    try:
                        conn = psycopg2.connect(**params)
                        logger.debug('search conn:%s', conn)
                        cur = conn.cursor()
                        print (q_data)
                        print (query)
                        logger.debug(query % q_data)
                        # logger.debug('search posts query:%s', query % (timestamp, limit))
                        cur.execute(query, q_data)
                        
                        items = cur.fetchall()
                        logger.debug("search item response %s" % (items))
                        if len(items) == 0:
                            logger.debug("NONE fetch for query %s" % (query))
                            return jsonify(status="OK",  items=[])
                        ret_items = []

                        i = items[0]
                        while len(items) > 0 and i[1] == None:
                            items.pop(0)
                            i = items[0]

                        d = {'id':i[1],
                            'username':i[0], 
                            'property':{'likes':i[7]}, 
                            'retweeted':i[6], 
                            'content':i[3], 
                            'timestamp': int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%d %H:%M:%S'))),
                            'childType':i[4], 
                            'parent':i[5]
                        }
                        current = d['id']
                        media = [] 
                        items.append(None) # just a footer to indicate end of items reached 

                        for i in items:
                            if i == None or i[1] != current:
                                d["media"] = media
                                ret_items.append(d)
                                if i != None:
                                    # clear media and make new d
                                    media = [] 
                                    if i[8] != None:
                                        media.append(i[8])
                                    d = {'id':i[1],
                                        'username':i[0], 
                                        'property':{'likes':i[7]}, 
                                        'retweeted':i[6], 
                                        'content':i[3], 
                                        'timestamp': int(time.mktime(time.strptime(str(i[2]).split('.')[0], '%Y-%m-%d %H:%M:%S'))),
                                        'childType':i[4], 
                                        'parent':i[5]
                                    }
                                    current = i[1]

                            else:
                                if i[1] == None:
                                    pass
                                if i[8] != None:
                                    media.append(i[8])

                        if cur != None:
                            cur.close()
                        if conn != None:
                            conn.close()
                        return jsonify(status="OK", items=ret_items)
                    except Exception as e:
                        if cur != None:
                            cur.close()
                        if conn != None:
                            conn.close()
                        print (traceback.format_exc())
                        logger.debug(e)
                        logger.debug(traceback.format_exc())
                        return jsonify(status="error", error="Connection error while searching for items")
            except Exception as ee:
                logger.debug(ee)
                logger.debug(traceback.format_exc())
                logger.warn("MEEEP")
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
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
            query="DELETE FROM posts where postid = %s RETURNING child_type, parent_id ;"
            logger.debug("delete query %s", query % (str(id)))
            cur.execute(query, (str(id), )) 
            rez = cur.fetchone()

            postid = rez[1]
            if rez != None and len(rez) > 0 and rez[0] == "retweet":
                query2 ="UPDATE posts set retweet_cnt = retweet_cnt-1 where username=%s and postid=%s;"
                try:
                   _thread.start_new_thread(send_delete_node, (postid, ) )
                except Exception as e:
                   logger.debug('Error on thread for email: %s', e)
                   logger.debug(traceback.format_exc())

                cur.execute(query2, (user_cookie, postid,))


            cur.close()
            conn.commit()
            conn.close()
        else: 
            conn.close()
            return jsonify(status="error", error="User not logged in")
    except Exception as e:
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
        return jsonify(status="error", error="item not deleted....")
        es.delete(index=INDEX_NAME, id=postid, ignore=[400, 404])
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
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
    except Exception as e:
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
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
            if cur != None:
                cur.close()
            if conn != None:
                conn.commit()
                conn.close()
            return jsonify(status="OK",users=followers)

    except Exception as e:
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
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
            if cur != None:
                cur.close()
            if conn != None:
                conn.commit()
                conn.close()
            return jsonify(status="OK",users=followings)
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()

    except Exception as e:
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
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
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
        return jsonify(status="error",error="Invalid request - send json please.")
        
    except Exception as e:
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
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
                    # Unlike
                    query = "DELETE FROM likes where username=%s and postid=%s RETURNING *"
                    cur.execute(query, (user_cookie, post_id,))
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
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
        return jsonify(status="error",error="Invalid request - send json please.")
        
    except Exception as e:
        # logger.debug(traceback.format_exc())
        if cur != None:
            cur.close()
        if conn != None:
            conn.commit()
            conn.close()
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

    
