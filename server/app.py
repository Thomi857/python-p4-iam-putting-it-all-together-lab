#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# Helper function for standardized error responses
def make_error_response(message, status_code):
    return make_response({"errors": [message]}, status_code)

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not (username and password):
            return make_error_response("Username and password are required.", 422)

        try:
            new_user = User(
                username=username,
                password=password, # Pass the password to the __init__ method
                image_url=image_url,
                bio=bio
            )

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return make_response(new_user.to_dict(rules=('-recipes',)), 201)

        except ValueError as e:
            db.session.rollback()
            return make_error_response(str(e), 422)
        except IntegrityError:
            db.session.rollback()
            return make_error_response("Username already exists. Please choose a different username.", 422)
        except Exception as e:
            db.session.rollback()
            return make_error_response(f"An unexpected error occurred: {str(e)}", 500)

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:

                return make_response(user.to_dict(rules=('-recipes',)), 200)
        return make_error_response("Unauthorized", 401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            
            return make_response(user.to_dict(rules=('-recipes',)), 200)
        else:
            return make_error_response("Invalid username or password", 401)

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id', None)
            return make_response({}, 204) 
        else:
            return make_error_response("Unauthorized", 401)

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_error_response("Unauthorized", 401)

        recipes = Recipe.query.all()

        return make_response([recipe.to_dict(rules=('user',)) for recipe in recipes], 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_error_response("Unauthorized", 401)

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id 
            )
            db.session.add(new_recipe)
            db.session.commit()

            return make_response(new_recipe.to_dict(rules=('user',)), 201)

        except ValueError as e:
            db.session.rollback()
            return make_error_response(str(e), 422)
        except Exception as e:
            db.session.rollback()
            return make_error_response(f"An unexpected error occurred: {str(e)}", 500)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    if app.secret_key == b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K':
        print("WARNING: Using default secret key. Set FLASK_SECRET_KEY in environment for production!")
    app.run(port=5555, debug=True)