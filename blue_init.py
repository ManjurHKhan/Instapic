from flask import Flask

app = Flask(__name__)

from api import mod as api_routes
from site import mod as site_routes

app.register_blueprint(site_routes, url_prefix ='/site')
app.register_blueprint(api_routes))

if __name__ == "__main__":
    app.run(host='0.0.0.0')
