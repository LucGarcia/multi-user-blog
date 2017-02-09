# Import libraries and database.
import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
import string
from google.appengine.ext import db

# Set up Jinja environment for templates. Enable automatic escaping of html.
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)



def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

def hash_str(s):
    return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Create class Handler, with functions that all handlers need.


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        name = self.read_secure_cookie('user_id')
        self.user = User.by_name(name)

    def like(self, post_id):
        p = Post.get_by_id(int(post_id))
        l = Like(user=self.user, post=p)
        l.put()
        p.likes += 1
        p.put()

    def unlike(self, post_id):
        p = Post.get_by_id(str(post_id))
        l = db.GqlQuery('select * from Comment where post = :1 and user = :2', p, str(self.user))
        l.delete()
        p.likes -= 1
        p.put()

# Create database classes.

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def login_check(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    user = db.ReferenceProperty(User, required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)


class Comment(db.Model):
    user = db.ReferenceProperty(User)
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post)


class Like(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)

    @classmethod
    def by_user(cls, user):
        likes = cls.all().filter('ancestor =', user).get()
        return likes

    @classmethod
    def by_post_id(cls, post_id):
        likes = cls.all().filter('post =', post_id).get()
        return likes



# Create handlers for the blog pages.


class MainPage(Handler):

    def render_front(self, posts=""):
        posts = db.GqlQuery(" select * from Post "
                            " order by created desc limit 10 ")
        self.render("front.html", posts=posts)


    def get(self):
        self.render_front()

    def post(self):
        like = self.request.get('like')
        unlike = self.request.get('unlike')
        post_id = self.request.get('post_id')
        p = Post.get_by_id(int(post_id))
        if self.user.name == p.user.name:
            self.redirect('/')

        else:
            if like:
                self.like(like)
                self.redirect('/')
            if unlike:
                self.unlike(unlike)
                self.redirect('/')


class Permalink(Handler):

    def get(self, post_id, comments=''):
        p = Post.get_by_id(int(post_id))
        self.render("post.html", post=p)

    def post(self, post_id, comments=''):
        content = self.request.get('comment')
        p = Post.get_by_id(int(post_id))
        if content:
            c = Comment(user=self.user,
                        content=content,
                        post=p)
            c.put()
            self.redirect("/%s" % post_id)


class Newpost(Handler):

    def render_form(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject,
                    content=content,
                    error=error)

    def get(self):
        if self.user:
            self.render_form()
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            p = Post(subject=subject,
                     content=content,
                     user=self.user,
                     likes=0)
            p.put()
            post_id = int(p.key().id())
            self.redirect("/%s" % post_id)
        else:
            error = "we need both a subject and some content!"
            self.render_form(subject, content, error)

### User Accounts related ###

secret = 'peppermint'

# Functions to create secure passwords and check them.


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)


# Create class User for the database.


# Create validators for username, password and email in form.


user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return user_re.match(username)

password_re = re.compile(r"^.{3,20}$")


def valid_userpassword(userpassword):
    return password_re.match(userpassword)

email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_useremail(useremail):
    return not useremail or email_re.match(useremail)

# Create handlers for user account paths.
class Signup(Handler):

    def get(self):
        self.render('signup.html')

    def post(self):
        # Get data from form and validate it.
        have_error = False
        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        params = dict(name=user_name,
                      email=user_email)
        valid_name = valid_username(user_name)
        valid_password = valid_userpassword(user_password)
        valid_email = valid_useremail(user_email)
        valid_verify = (user_verify == user_password)
        # return form with errors if data is not valid.
        if not valid_name:
            params['error_name'] = "Oops, that ain't a valid name!"
            have_error = True
        if not valid_password:
            params['error_password'] = "Oops, that ain't a valid password!"
            have_error = True
        if not valid_verify:
            params['error_verify'] = "Oops, your passwords ain't matching!"
            have_error = True
        if not valid_email:
            params['error_email'] = "Oops, that ain't a valid e-mail!"
            have_error = True
        if have_error:
            self.render('signup.html', **params)
        # Check if username exists and return error if so.
        else:
            u = User.by_name(user_name)
            if u:
                msg = 'Oops, that name already exists!'
                self.render('signup.html', error_username=msg)
            # Register User and redirect to welcome page.
            else:
                u = User(name=user_name,
                         pw_hash=make_pw_hash(user_name, user_password),
                         email=user_email)
                u.put()
                self.set_secure_cookie('user_id', str(user_name))
                self.redirect('/welcome')


class Welcome(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html')
        else:
            self.redirect('/signup')


class Login(Handler):

    def get(self):
        if user:
            self.redirect('/logout')
        else:
            self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login_check(username, password)
        if u:
            self.set_secure_cookie('user_id', str(username))
            self.redirect('/welcome')
        else:
            msg = "Oops, that login ain't valid!"
            self.render('login.html', error_login=msg)


class Logout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')



# Define app and assign handlers to paths.
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', Newpost),
    ('/(\d+)', Permalink),
    ('/signup', Signup),
    ('/welcome', Welcome),
    ('/login', Login),
], debug=True)
