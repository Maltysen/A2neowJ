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


JUDGE_TYPES = {
	"UNKNOWN": 0,
	"CODEFORCES": 1,
}

def compute_url(self):
	if self.judge_type == JUDGE_TYPES['CODEFORCES']:
		kind = "gym" if self.contest_id>=100000 else "contest"
		return "http://codeforces.com/%s/%s/problem/%s"%(kind, self.contest_id, self.index)

	raise NotImplementedError(self.judge_type)

class Problem(ndb.Model):
	name = ndb.StringProperty()
	added = ndb.DateTimeProperty(auto_now_add=True)
	judge_type = ndb.IntegerProperty(choices = JUDGE_TYPES.values())

	#Codeforces info
	contest_id = ndb.IntegerProperty()
	index = ndb.StringProperty()

	url = ndb.ComputedProperty(compute_url)

class Ladder(ndb.Model):
	name = ndb.StringProperty()
	problems = ndb.KeyProperty(kind=Problem, repeated=True)
	created = ndb.DateTimeProperty(auto_now_add=True)

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

	cf_username = ndb.StringProperty()
	cf_read_from = ndb.IntegerProperty(default=1)

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

def konekolize_problem(judge_type, **kwargs):
	judge_type = int(judge_type)

	if judge_type == JUDGE_TYPES["CODEFORCES"]:
		contest_id = int(kwargs['contestId'])
		index = kwargs['index'].upper()

		problem = Problem.query(Problem.judge_type == judge_type, Problem.contest_id==contest_id, Problem.index==index).get()
		if problem: return problem
		problem = Problem(judge_type=judge_type, contest_id=contest_id, index=index)
		problem.name = requests.get(problem.url).text.split('<div class="title">')[1].split("</div>")[0].split(". ", 1)[1]
		problem.put()
		return problem

	raise NotImplementedError(judge_type)

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

@app.route('/admin/add_ladder', methods=['GET', 'POST'])
def add_ladder():
	if request.method=='GET':
		return render_template("add_ladder.html")
	
	name = request.form.get("name")
	if not name:
		return "<h1>Didn't provide name for ladder</h1>"

	ladder = Ladder(name=name)
	ladder.put()
	return "<h1>Ladder '%s' created successfully</h1>"%name

@app.route('/admin/edit_ladder', methods=['GET', 'POST'])
def edit_ladder():
	ladders = Ladder.query().fetch()

	if request.method=='GET':
		return render_template("edit_ladder.html", ladders=ladders, judge_types=JUDGE_TYPES)
	
	try:
		problem = konekolize_problem(**request.form.to_dict())
	except Exception as e:
		raise e
		return "<h1>Issue adding problem</h1>"

	ladder = Ladder.get_by_id(int(request.form.get("ladder_id")))
	if not ladder:
		return "<h1>Couldn't find ladder</h1>"

	if problem.key not in ladder.problems:
		ladder.problems.append(problem.key)
		ladder.put()
		return render_template("edit_ladder.html", ladders=ladders, judge_types=JUDGE_TYPES, succ=True)
	else:
		return "<h1>Problem already inside ladder</h1>"
		

