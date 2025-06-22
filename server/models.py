from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship to Recipe
    recipes = db.relationship('Recipe', backref='user', lazy=True, cascade='all, delete-orphan')

    # !!! REMOVED serialize_rules from User to allow test_has_list_of_recipes to pass !!!
    # Control serialization in app.py directly using to_dict(rules=...)
    # serialize_rules = ('-recipes',) # <-- REMOVE THIS LINE
    
    # You might still want to exclude _password_hash from general serialization
    # if you want this to be the default for ALL user.to_dict() calls.
    # If not, you'll need to specify it when calling to_dict().
    serialize_rules = ('-_password_hash',) # Keep this for password hash

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter # Corrected decorator for consistency
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash.encode('utf-8'), password.encode('utf-8'))

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username must be present.")
        return username

    def __repr__(self):
        return f'<User {self.username}>'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # This rule is correct and necessary for nested serialization
    serialize_rules = ('-user.recipes',)

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title must be present.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions:
            raise ValueError("Instructions must be present and at least 50 characters long.")
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    def __repr__(self):
        return f'<Recipe {self.title}>'