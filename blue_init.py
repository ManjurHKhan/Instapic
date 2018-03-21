from flask import Flask

app = Flask(__name__)

from blue.api.routes import mod
from blue.site.routes import mod

app.register_blueprint(site.routes.mod, url_prefix ='/site')
app.register_blueprint(api.routes.mod)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
