from ast import Raise
import flask
from werkzeug.debug import DebuggedApplication

app = flask.Flask(__name__)
app.config["template_folder"] = "interface/templates"
app.config["static_folder"] = "interface/public"
app.config["static_url_path"] = "/public"

@app.route('/home')
@app.route('/')
def index():
    return flask.render_template('index.html')

if __name__ == '__main__':
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)
    app.run(debug=True)
