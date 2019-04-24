from flask import Flask
from flask import request, session

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
	string = '{args.get.__func__.__globals__[mimetypes].os.environ}'.format(args=request.args)
	return string

if __name__ == '__main__':
	app.run()