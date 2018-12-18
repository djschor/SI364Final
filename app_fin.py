
'''
Questions: 

- how to get current user id
- youtube api 
    - cannot import argparse
- datetime fields and automatic entering 
- embedding graphs into app
'''

import os
import requests
import json, urllib
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError, IntegerField, DateField
#from wtforms.fields.html5 import DateField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from apiclient.discovery import build
from apiclient.errors import HttpError
from oauth2client.tools import argparser
import json

DEVELOPER_KEY = 'AIzaSyBPQoXAHKFms-a3FP7BUlacTCpgLKOhl-Y'
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"

############################
# Application configurations
############################
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hard to guess string from si364'
## TODO 364: Create a database in postgresql in the code line below, and fill in your app's database URI. It should be of the format: postgresql://localhost/YOUR_DATABASE_NAME

## Your final Postgres database should be your uniqname, plus HW5, e.g. "jczettaHW5" or "maupandeHW5"
app.config["SQLALCHEMY_DATABASE_URI"] =  "postgres://postgres:snubbalo@localhost/djschorFinal"
## Provided:
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager


##################
### App setup ####
##################
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

## Set up Shell context so it's easy to use the shell to debug
# Define function
def make_shell_context():
    return dict( app=app, db=db)
# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))

#########################
##### Set up Models #####
#########################

## All provided.

# Association tables
#on_list = db.Table('on_list',db.Column('item_id',db.Integer, db.ForeignKey('items.id')),db.Column('list_id',db.Integer, db.ForeignKey('lists.id')))

tags = db.Table('tags',db.Column('search_id',db.Integer, db.ForeignKey('searchTerm.id')),db.Column('vid_id',db.Integer, db.ForeignKey('videos.id')))

user_collection = db.Table('user_collection',db.Column('vid_id', db.Integer, db.ForeignKey('videos.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalVideoCollections.id')))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    activities = db.relationship('Activity', backref='users') #change 
    goals = db.relationship('Goal', backref='users')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property    #test this and below
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id)) # returns User object or None

class Activity(db.Model):
    __tablename__ = "activities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(225))
    value = db.Column(db.Integer)
    date = db.Column(db.Date()) #is this correct? Currently use DateField in WTForm 
    comment = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

class Goal(db.Model):
    __tablename__ = "goals"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    text = db.Column(db.String(225))
    priority = db.Column(db.Integer)
    date = db.Column(db.Date) 
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

class Video(db.Model): 
    __tablename__ = "videos"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(225))
    embedURL = db.Column(db.String(256))

    def __repr__(self):
        return "{}, URL: {}".format(self.title,self.embedURL)

class PersonalVideoCollection(db.Model):
     __tablename__ = "personalVideoCollections"
     id = db.Column(db.Integer, primary_key=True)
     name = db.Column(db.String(255))
     user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
     videos = db.relationship('Video',secondary=user_collection,backref=db.backref('personalVideoCollections',lazy='dynamic'),lazy='dynamic')

class SearchTerm(db.Model):
    __tablename__ = "searchTerm"
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(32),unique=True) # Only unique searches
    videos = db.relationship('Video',secondary=tags,backref=db.backref('searchTerm',lazy='dynamic'),lazy='dynamic')

    def __repr__(self):
        return "{} : {}".format(self.id, self.term)
########################
##### Set up Forms #####
########################

# Provided - Form to create a todo list
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')   

class VideoSearchForm(FlaskForm):
    search = StringField("Enter a term to search for inspirational videos", validators=[Required()])
    submit = SubmitField('Submit')


class CollectionCreateForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    vid_picks = SelectMultipleField('Videos to include', coerce=int)
    submit = SubmitField("Create Collection")


class ActivityForm(FlaskForm): 
    name = StringField('Activity Name',validators=[Required()])
    value = IntegerField('Quality Value', validators=[Required()])
    date = DateField('Date of Activity', format = '%Y-%m-%d', validators=[Required()])
    comment = StringField('Comments')
    submit = SubmitField("Submit Activity Log")

class GoalForm(FlaskForm): 
    name = StringField('What is the name of your Goal?',validators=[Required()])
    text = StringField('What is your goal?',validators=[Required()])
    priority = StringField('What is the priority of your goal?',validators=[Required()])
    date = DateField('Date of goal', validators=[Required()])
    submit = SubmitField("Enter Activity")




################################
####### Helper Functions #######
################################

## Provided.

def get_vids_from_youtube(search_string):
    """ Returns data from Youtuve API with up to 5 videos corresponding to the search input"""
    baseurl = "https://www.googleapis.com/youtube/v3/search"
    youtube = build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION,
    developerKey=DEVELOPER_KEY)

    search_response = youtube.search().list(
    q=search_string,
    type="video",
    pageToken=None,
    order = "relevance",
    part="id,snippet",
    maxResults=5,
    location=None,
    locationRadius=None).execute()
    videos = []
    for search_result in search_response.get("items", []):
        if search_result["id"]["kind"] == "youtube#video":
            videos.append(search_result)

    items_to_embed = []
    for item in search_response['items']:
        if 'videoId' in item['id']:
            item['url'] = 'https://www.youtube.com/embed/{0}'.format(item['id']['videoId'])
            items_to_embed.append(item)
    #return render_template('all_videos.html', all_vids=items_to_embed, search_term="search_string")
    return items_to_embed

'''def get_or_create_activity(db_session, name, value, date, comment, user_id):
    item = Activity(name=name, value = value, date = date, comment = comment, user_id = user_id)
    db_session.add(item)
    db_session.commit()
    return item
'''
def get_vid_by_id(id):
    """Should return gif object or None"""
    v = Video.query.filter_by(id=id).first()
    return v

def get_or_create_video(title, url):
    video = Video.query.filter_by(title = title).first()
    if video:
        return video
    else:
        video = Video(title = title, embedURL = url)
        db.session.add(video)
        db.session.commit()
        return video

def get_or_create_goal(name, text, priority, date, user_id):
    goal = Goal.query.filter_by(text = text).first()
    if goal:
        return goal
    else:
        item = Goal(name = name, text = text, priority = priority, date = date, user_id = user_id)
        db.session.add(item)
        db.session.commit()
        return item

def get_or_create_search_term(term):
    searchTerm = SearchTerm.query.filter_by(term=term).first()
    if searchTerm:
        print("Found term")
        return searchTerm
    else:
        term=term
        print("Added term")
        searchTerm = SearchTerm(term=term)
        vid_data = get_vids_from_youtube(term)
        print(vid_data)
        vid_list = []
        for vid in vid_data: #iterates through list of 5 dictionaries
            title = vid['title']
            url = vid['url']
            function_results = get_or_create_video(title, url)
            searchTerm.videos.append(function_results)
            #vid_list.append(function_results)
        db.session.add(searchTerm)
        db.session.commit()
        return searchTerm

def get_or_create_collection(name, current_user, video_list=[]):
    """Always returns a PersonalGifCollection instance"""
    vidCollection = PersonalVideoCollection.filter_by(name=name,user_id=current_user.id).first()
    if vidCollection:
        return vidCollection
    else:
        vidCollection = PersonalVideoCollection(name=name,user_id=current_user.id, videos=[])
        for a in video_list:
            vidCollection.videos.append(a)
        db.session.add(vidCollection)
        db.session.commit()
        return vidCollection
###################################
##### Routes & view functions #####
###################################

## Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

## Login-related routes 
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/videos_searched/<search_term>')
def search_results(search_term):
    term = SearchTerm.query.filter_by(term=search_term).first()
    relevant_videos = term.videos.all()
    return render_template('searched_videos.html',videos=relevant_videos,term=term)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."


@app.route('/', methods=["GET","POST"])
def index():
    form = ActivityForm() #ALL ACTIVITIES
    activities = Activity.query.all()
    active_list = []
    for a in activities: 
        name = a.name 
        active_list.append(name)
    active_set = set(active_list) #SET OF UNIQUE ACTIVITIES
    len_set = len(active_set)
    '''
    form_vid = VideoSearchForm()
    #videos = Video.query.all() #ALL VIDEOS (NOT IN COLLECTION)
    if form_vid.validate_on_submit(): 

        if db.session.query(SearchTerm).filter_by(term=form_vid.search.data).first():
            term = db.session.query(SearchTerm).filter_by(term=form_vid.search.data).first()
            all_vids = []
            for v in term.videos.all():
                all_vids.append((v.title, v.embedURL))
            print(all_vids)
            return render_template('all_videos.html', all_vids = all_vids)
        else:
            search = form_vid.search.data
            new_search = get_or_create_search_term(search)
            return redirect(url_for('search_results'))
'''
    collection = PersonalVideoCollection.query.all() #collection
    count = Activity.query.count() #COUNT OF LOGGED ACTIVITIES

    form_user = LoginForm() #attempt at getting user information 
    if request.method == 'POST':
        name = form.name.data
        comment = form.comment.data
        value = form.value.data
        date = form.date.data
        user_id = current_user.id
        print(name, date, value, comment)
        #new_activity = get_or_create_activity(db.session, name, value, date, comment, user_id) 
        item = Activity(name=name, value = value, date = date, comment = comment, user_id = user_id)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('activity_log'))
    return render_template('index.html',form=form, count = count, collection = collection, active_set = active_set, len_set = len_set)

@app.route('/log')
def activity_log():
    all_activities = []
    lsts = Activity.query.all()
    #for a in lsts: 
    #    items = TodoItem.query.filter_by(id = a.list_id).first()
    #    all_activities.append((a.name, a.value, a.))
    return render_template('activity_log.html',activities=lsts)

@app.route('/all_videos')
def all_videos(search_term):
    vids = Video.query.all()
    return render_template('all_videos.html',all_videos=vids)

@app.route('/goals',methods=["GET","POST"])
@login_required
def goals():
    form = GoalForm()
    goals = Goal.query.all()
    if request.method == "POST":
        name = form.name.data
        text = form.text.data
        priority = form.priority.data
        date = form.date.data
        user_id = current_user.id
        new_goal = get_or_create_goal(name, text, priority, date, user_id)
        return redirect(url_for('goals'))
    return render_template('goals.html', goals = goals, form = form)

@app.route('/create_collection',methods=["GET","POST"])
@login_required
def create_collection():
    form = CollectionCreateForm()
    vids = Video.query.all()
    choices = [(v.id, v.title) for v in vids]
    form.vid_picks.choices = choices
    if form.validate_on_submit(): 
        vids = form.vid_picks.data
        vid_list = []
        for vid in vids: 
            vid_obj = get_vid_by_id(vid)
            vid_list.append(vid_obj)
        get_or_create_collection(form.name.data, choices[0],vid_list)
        return redirect(url_for('inspiration'))
    else: 
        return render_template('create_collection.html', form = form, choices = choices)

@app.route('/inspiration',methods=["GET","POST"])
def inspiration():
    form = VideoSearchForm()
    collection = PersonalVideoCollection.query.all()
    len_col = len(collection)

    if request.method == "POST":
        search = form.search.data
        new_search = get_or_create_search_term(search)
        return redirect(url_for('search_results', search_term = new_search))

    return render_template('inspiration.html', collection = collection, form = form, len_col = len_col)

'''
    form_vid = VideoSearchForm()
    #videos = Video.query.all() #ALL VIDEOS (NOT IN COLLECTION)
    if form_vid.validate_on_submit(): 

        if db.session.query(SearchTerm).filter_by(term=form_vid.search.data).first():
            term = db.session.query(SearchTerm).filter_by(term=form_vid.search.data).first()
            all_vids = []
            for v in term.videos.all():
                all_vids.append((v.title, v.embedURL))
            print(all_vids)
            return render_template('all_videos.html', all_vids = all_vids)
        else:
            search = form_vid.search.data
            new_search = get_or_create_search_term(search)
            return redirect(url_for('search_results'))
'''
if __name__ == "__main__":
    db.create_all()
    manager.run()