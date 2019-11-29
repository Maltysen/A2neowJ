from flask import Flask, render_template, request, redirect, make_response, Response, abort
from google.appengine.ext import ndb
from google.appengine.api import memcache
import urllib
import os
import hashlib
import codecs
from Crypto.Hash import SHA256, HMAC
from secrets import *
import requests
import requests_toolbelt.adapters.appengine

requests_toolbelt.adapters.appengine.monkeypatch()


class User(ndb.Model):
	username = ndb.StringProperty()
	username_lower = ndb.ComputedProperty(lambda self: self.username.lower())
	password = ndb.StringProperty()
	email = ndb.StringProperty()
	created = ndb.DateTimeProperty(auto_now_add=True)
	validated = ndb.BooleanProperty(default=False)
	validation_link = ndb.StringProperty()
	reset_link = ndb.StringProperty()
	reset_expire = ndb.DateTimeProperty()
	num_logins = ndb.IntegerProperty(default=0)

def make_hash(password, salt):
	h = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
	return codecs.encode(salt, "hex")+","+codecs.encode(h, "hex")

def send_message(to, subject, body):
	print subject, body
	#return requests.post(
	#	"https://api.mailgun.net/v3/writemycs.com/messages",
	#	auth=("api", mailgun_key),
	#	data={"from": "Write My CS <noreply@writemycs.com>",
	#		  "to": to,
	#		  "subject": subject,
	#		  "html": body})

def require_login(func):
	def f():
		token = request.cookies.get('sessionid') or ''
		kid = memcache.get(token)
		user = User.get_by_id(kid) if kid else None
		if not user:
			resp = redirect('/login?redirect='+urllib.quote(request.full_path, safe=''))
			resp.set_cookie('sessionid', '', expires=0)
			return resp
		return func(user)

	f.__name__ = func.__name__
	return f

def no_login(func):
	def f():
		token = request.cookies.get('sessionid') or ''
		if not token:
			return func()
		kid = memcache.get(token)
		user = User.get_by_id(kid) if kid else None
		if not user:
			a=make_response(func())
			a.set_cookie('sessionid', '', expires=0)
			return a
		return redirect('/')

	f.__name__ = func.__name__
	return f

def pick_login(func):
	def f():
		token = request.cookies.get('sessionid') or ''
		if not token:
			return func(None)
		kid = memcache.get(token)
		user = User.get_by_id(kid) if kid else None
		if not user:
			a=make_response(func(None))
			a.set_cookie('sessionid', '', expires=0)
			return a
		return func(user)

	f.__name__ = func.__name__
	return f

def verify_captcha(action=None):
	ret = requests.post("https://www.google.com/recaptcha/api/siteverify", {"secret": RECAPTCHA_SECRET_KEY, "response": request.form.get("g-recaptcha-response"), "remoteip": request.remote_addr}).json()
	return ret["success"]

app = Flask(__name__, template_folder='.', static_folder='.')
app.jinja_env.globals['recaptcha_key'] = recaptcha_key

@app.route('/')
@pick_login
def root(user):
    return render_template('index.html', user=user)

@app.route('/verify_register')
@no_login
def verify_register():
	u = request.args.get("username").lower()
	e = request.args.get("email")
	if User.query(User.username_lower==u).count():
		return "username exists"
	if User.query(User.email==e).count():
		return "email exists"
	return "validated"

@app.route('/register', methods=['GET', 'POST'])
@no_login
def register():
	if request.method=='POST':
		if not verify_captcha():
			return redirect('register')
		u = request.form.get("username").lower()
		e = request.form.get("email")
		if User.query(User.username_lower==u).count() or len(u)<6:
			return render_template("register.html")
		if User.query(User.email==e).count():
			return render_template("register.html")
		user = User(username=request.form.get("username"), password=make_hash(request.form.get("password"), os.urandom(8)), email=e, validation_link=SHA256.new(os.urandom(32)).hexdigest())
		user.put()

		#send_message(
		#	to=e,
		#	subject="Validate your Email for A2neowJ",
		#	body=app.jinja_env.get_template("emails/email_welcome.html").render(user=user))

		return redirect('login?welcome')

	return render_template("register.html")

def verify_login():
	user = User.query(User.username_lower == request.form.get("username").lower()).get()
	if user:
		if user.num_logins >= 5 and not verify_captcha():
			return True
		if make_hash(request.form.get("password"), codecs.decode(user.password.split(",")[0], "hex"))==user.password:
			if user.validated==False:
				return -1
			user.num_logins=0
			user.put()
			token = codecs.encode(os.urandom(16), "hex")
			memcache.add(token, user.key.id())
			resp = make_response(redirect(request.args.get('redirect')) if request.args.get('redirect') else redirect("/"))
			resp.set_cookie('sessionid', token)
			return resp
		user.num_logins += 1
		user.put()
		return user.num_logins >= 5
	return False

@app.route('/verify_email')
@no_login
def verify_email():
	user = User.query(User.validation_link==request.args.get("id")).get()
	if (not user) or user.validated:
		return redirect('login')
	user.validated=True
	user.put()
	return redirect('login?valid')

@app.route('/login', methods=['GET', 'POST'])
@no_login
def login():
	if request.method=='GET':
		return render_template("login.html", new=request.args.get("welcome"), valid=request.args.get("valid"), reset=request.args.get("reset"), requested=request.args.get("requested"))
	verify = verify_login()
	if verify==-1:
		return render_template("login.html", unvalid=True)
	if verify==True:
		return render_template("login.html", invalid=True, captcha=True)
	if verify==False:
		return render_template("login.html", invalid=True)
	return verify

@app.route('/logout')
@require_login
def logout(user):
	token = request.cookies.get('sessionid')
	memcache.delete(token)
	resp = redirect('/')
	resp.set_cookie('sessionid', '', expires=0)
	return resp


