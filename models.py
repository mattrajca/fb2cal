from google.appengine.ext import db
import hashlib

class User(db.Model):
	password = db.StringProperty() # store as hash
	access_token = db.StringProperty()
	uid = db.StringProperty()
	
	def set_password(self, password):
		self.password = hashlib.md5(password).hexdigest()
	
	def is_password_valid(self, password):
		hash = hashlib.md5(password).hexdigest()
		return hash == self.password

