from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


@app.route('/')
def home():
    # Sample data
    user_name = "John Doe"
    user_email = "johndoe@example.com"
    app_name = "My Flask App"
    app_version = "1.0"
    app_status = "Running"
    commands = ["Command 1", "Command 2", "Command 3"]

    return render_template('home.html', user_name=user_name, user_email=user_email,
                           app_name=app_name, app_version=app_version,
                           app_status=app_status, commands=commands)

@app.route('/debugging')
def debugging():
    return render_template('debugging.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/add_tab', methods=['GET', 'POST'])
def add_tab():
    if request.method == 'POST':
        tab_name = request.form['tab_name']
        # Add logic to create a new tab and update the navigation bar
        return redirect(url_for('home'))
    else:
        return render_template('add_tab.html')

if __name__ == '__main__':
    app.run(debug=True)

