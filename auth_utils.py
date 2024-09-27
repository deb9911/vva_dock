# auth_utils.py

def authenticate(username, password):
    # Example: Fetch user from database (using SQLAlchemy or any ORM)
    user = User.query.filter_by(username=username).first()

    # Check if the user exists and the password matches
    if user and user.check_password(password):  # Assuming check_password is a method to verify the password
        return user
    return None
