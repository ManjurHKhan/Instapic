from flask import Flask


app = Flask(__name__)

app.secret_key = 'prsW3dojaskl12=121341x3'

from insta.api import mod as api_routes
from insta.site import mod as site_routes

app.register_blueprint(site_routes, url_prefix ='/site')
app.register_blueprint(api_routes)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
