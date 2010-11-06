#!/usr/bin/env python

from django.utils import simplejson as json
from google.appengine.api import memcache
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp import util
from models import *

import base64
import facebook
import os
import urllib

FACEBOOK_APP_ID = ""
FACEBOOK_APP_SECRET = ""

def user_from_cookies(handler):
	cookie = facebook.get_user_from_cookie(handler.request.cookies, FACEBOOK_APP_ID, FACEBOOK_APP_SECRET)
	
	if cookie:
		uid = cookie["uid"]
		token = cookie["access_token"]
		
		user = User.get_by_key_name(uid)
		
		if not user:
			user = User(key_name=uid, uid=uid, access_token=token)
			user.put()
		elif user.access_token != token:
			user.access_token = token
			user.put()
		
		return user
	
	return None


def prompt_auth(response):
	response.set_status(401, message="Authorization Required")
	response.headers['WWW-Authenticate'] = 'Basic realm="Secure Area"'


def check_auth(handler):
	auth = handler.request.headers.get('Authorization')
	
	if not auth:
		prompt_auth(handler.response)
		return None
	
	auth_parts = auth.split(' ')
	user_pass_parts = base64.b64decode(auth_parts[1]).split(':')
	user_arg = user_pass_parts[0]
	pass_arg = user_pass_parts[1]
	
	user = User.get_by_key_name(user_arg)
	
	if not user:
		prompt_auth(handler.response)
		return None
	
	if not user.is_password_valid(pass_arg):
		prompt_auth(handler.response)
		return None
	
	return user


def render(handler, path, values):
	path = os.path.join(os.path.dirname(__file__), "templates", path)
	handler.response.out.write(template.render(path, values))


class HomeHandler(webapp.RequestHandler):
	def get(self):
		user = user_from_cookies(self)
		
		if user is None:
			render(self, "welcome.html", { 'facebook_app_id': FACEBOOK_APP_ID })
		elif user.password is None:
			self.redirect("/setupAccount")
		else:
			self.redirect("/main")


class PrivacyHandler(webapp.RequestHandler):
	def get(self):
		render(self, "privacy.html", None)


class EmptyCacheHandler(webapp.RequestHandler):
	def get(self):
		user = user_from_cookies(self)
		
		if user.password is not None:
			memcache.delete(user.uid)
		
		self.redirect("/")


class SetupAccountHandler(webapp.RequestHandler):
	def get(self):
		user = user_from_cookies(self)
		
		if user is None:
			self.redirect("/")
			return
		
		render(self, "account.html", { 'uid': user.uid })


class MainHandler(webapp.RequestHandler):
	def get(self):
		user = user_from_cookies(self)
		
		if user is None or user.password is None:
			self.redirect("/")
			return
		
		render(self, "main.html", { 'facebook_app_id': FACEBOOK_APP_ID, 'uid': user.uid })


class SetPasswordHandler(webapp.RequestHandler):
	def get(self):
		user = user_from_cookies(self)
		
		if user is None:
			self.redirect("/")
			return
		
		user.set_password(self.request.get('password'))
		user.put()
		
		self.redirect("/main")


class BirthdaysHandler(webapp.RequestHandler):
	def get(self):
		cred = check_auth(self)
		
		if not cred:
			return
		
		uid = str(cred.uid)
		token = cred.access_token
		
		data = memcache.get(uid)
		
		if data is None:
			query = "select first_name,last_name,birthday_date,uid from user where uid in \
					 (select uid2 from friend where uid1 = %s)" % uid
			query = urllib.quote_plus(query)
			
			url = "https://api.facebook.com/method/fql.query?query=%s&access_token=%s&format=json" % (query, token)
			data = json.loads(urllib.urlopen(url).read())
			
			if data is None:
				return
			
			memcache.set(uid, data, 60 * 60 * 24 * 2)
		
		self.response.out.write("BEGIN:VCALENDAR\nMETHOD:PUBLISH\nVERSION:2.0\n")
		self.response.out.write("PRODID:-//mattrajca\n")
		
		for entry in data:
			name = entry['first_name'] + " " + entry['last_name'] + "'s Birthday"
			birthday = entry['birthday_date']
			f_uid = str(entry['uid'])
			
			if birthday and name and uid:
				self.response.out.write("BEGIN:VEVENT\n")
				
				comps = birthday.split('/')
				month = comps[0].zfill(2)
				day = comps[1].zfill(2)
				
				self.response.out.write("DTSTART:2008" + month + day + "\n")
				self.response.out.write("SUMMARY:" + name + "\n")
				self.response.out.write("UID:" + f_uid + "\n")
				self.response.out.write("TRANSP:TRANSPARENT\nCATEGORIES:BIRTHDAY\nRRULE:FREQ=YEARLY\nEND:VEVENT\n")
		
		self.response.out.write("END:VCALENDAR\n")


def main():
	debug = os.environ.get("SERVER_SOFTWARE", "").startswith("Development/")
	util.run_wsgi_app(webapp.WSGIApplication([
		("/", HomeHandler),
		("/birthdays.ics", BirthdaysHandler),
		("/setupAccount", SetupAccountHandler),
		("/setPassword", SetPasswordHandler),
		("/main", MainHandler),
		("/privacyPolicy", PrivacyHandler),
		("/emptyCache", EmptyCacheHandler)
	], debug=debug))


if __name__ == "__main__":
	main()
