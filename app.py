from flask import Flask, render_template

from search import api_search
from graph import make_graph
from cwe_graph import cwe_graph

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')

app.register_blueprint(api_search)
app.register_blueprint(make_graph)
app.register_blueprint(cwe_graph)

if __name__ == '__main__':
    app.run('0.0.0.0')

