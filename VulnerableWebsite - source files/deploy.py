from __init__ import create_app

app = create_app()

if __name__ == '__main__':
	app.run(debug=True)

# @app.route('/')
# def index():
# 	return '<h1>Deployed</h1>'