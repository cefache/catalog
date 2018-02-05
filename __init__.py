from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash, make_response, abort, g
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User


import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
from functools import wraps

auth = HTTPBasicAuth()
app = Flask(__name__)

CLIENT_ID = json.loads(open('/var/www/CatalogApp/catalog/client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = "catalog-application"

# Connect to Database and create database session
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_is_required(f):
    """
    Wrapper function to check if a user is logged in and thus can get access
    to certain create, edit or delete pages
    Args:
        f (function): to be wrapped
    Returns:
        decorated_function that checks for logged-in user
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access there")
            return redirect('/login')
    return decorated_function


@app.route('/')
@app.route('/catalog')
@app.route('/categories')
def showCategories():
    """
    Render home page showing all categories and latest items
    Args:
        -
    Returns:
        Rendered template of homepage
    """
    categories = session.query(Category).order_by(asc(Category.name))
    latest_items = session.query(Item).order_by(desc(Item.id)).limit(10)
    related_categories = []
    for item in latest_items:
        related_categories.append(session.query(Category)
                                  .filter_by(id=item.category_id)
                                  .one_or_none())
    latest_zip = zip(latest_items, related_categories)
    return render_template('catalog.html', categories=categories,
                           latest_zip=latest_zip,
                           username=login_session.get('username'))


@app.route('/category/new/', methods=['GET', 'POST'])
@login_is_required
def newCategory():
    """
    Render page for creating a new category and process creation in database
    Args:
        -
    Returns:
        Rendered template of page to create a new category if GET request,
        creation of a new category in the database if POST request
    """
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New category %s successfully created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newCategory.html', categories=categories,
                               username=login_session.get('username'))


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_is_required
def editCategory(category_id):
    """
    Render page for editing a category and process editing in database and
    process editing in database
    Args:
        category_id (integer): the category_id of the category to be edited
    Returns:
        Rendered template of page to edit the category in question if GET
        request, performed edit in the database of the category in question
        if POST request
    """
    editedCategory = (session.query(Category)
                      .filter_by(id=category_id).one_or_none())
    if editedCategory:
        if request.method == 'POST':
            if ((login_session.get('user_id') is not None) and
               (login_session['user_id'] == editedCategory.user_id)):
                if request.form['name']:
                    editedCategory.name = request.form['name']
                    flash('Category successfully edited %s'
                          % editedCategory.name)
                    return redirect(url_for('showCategories'))
            else:
                flash('You have no editing rights for this category!')
                return redirect(url_for('showItems', category_id=category_id))
        else:
            categories = session.query(Category).order_by(asc(Category.name))
            return render_template('editCategory.html', categories=categories,
                                   category=editedCategory,
                                   username=login_session.get('username'))
    else:
        flash('Category not found...')
        return redirect(url_for('showCategories'))


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_is_required
def deleteCategory(category_id):
    """
    Render page for deleting a category and process deletion in database
    Args:
        category_id (integer): the category_id of the category to be deleted
    Returns:
        Rendered template of page to delete the category in question if GET
        request, performed deletion of category in question if POST request
    """
    categoryToDelete = (session.query(Category)
                        .filter_by(id=category_id).one_or_none())
    if categoryToDelete:
        if request.method == 'POST':
            if ((login_session.get('user_id') is not None) and
               (login_session['user_id'] == categoryToDelete.user_id)):
                # delete all corresponding items first
                # itemsToDelete = (session.query(Item)
                #                  .filter_by(category_id=category_id).all())
                # for i in itemsToDelete:
                #     session.delete(i)
                session.delete(categoryToDelete)
                session.commit()
                flash('%s Successfully deleted' % categoryToDelete.name)
                return redirect(url_for('showCategories'))
            else:
                flash('You have no editing rights for this category!')
                return redirect(url_for('showItems', category_id=category_id))
        else:
            categories = session.query(Category).order_by(asc(Category.name))
            return render_template('deleteCategory.html',
                                   categories=categories,
                                   category=categoryToDelete,
                                   username=login_session.get('username'))
    else:
        flash('Category not found...')
        return redirect(url_for('showCategories'))


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showItems(category_id):
    """
    Render page for showing items of a specific category
    Args:
        category_id (integer): the category_id of the category for which the
                               items are to be showed
    Returns:
        Rendered template of page to show the items of the category
        in question
    """
    category = session.query(Category).filter_by(id=category_id).one_or_none()
    if category:
        items = session.query(Item).filter_by(category_id=category_id).all()
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('items.html', categories=categories,
                               items=items,
                               category=category,
                               username=login_session.get('username'),
                               user_id=login_session.get('user_id'))
    else:
        flash('Category not found...')
        return redirect(url_for('showCategories'))


@app.route('/item/<int:item_id>')
def showItem(item_id):
    """
    Render page for showing one specific item
    Args:
        item_id (integer): the item_id of the item to be showed
    Returns:
        Rendered template of page to show the specific item
    """
    item = session.query(Item).filter_by(id=item_id).one_or_none()
    if item:
        if item.category_id is not None:
            category = (session.query(Category)
                        .filter_by(id=item.category_id).one_or_none())
            items = (session.query(Item)
                     .filter_by(category_id=category.id).all())
        else:
            flash('No category assigned to this item')
            category = None
            items = None
        return render_template('item.html', category=category, item=item,
                               items=items,
                               username=login_session.get('username'),
                               user_id=login_session.get('user_id'))
    else:
        flash('Item not found...')
        return redirect(url_for('showCategories'))


@app.route('/item/new/', methods=['GET', 'POST'])
@login_is_required
def newItem():
    """
    Render page for creating a new item and process creation in database
    Args:
        -
    Returns:
        Rendered template of page to create a new item if GET request,
        processing of submitted data to create a new item if POST request
    """
    if request.method == 'POST':
        if login_session.get('user_id') is not None:
            # TODO: check category id
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           category_id=request.form['category_id'],
                           user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            flash('New item %s successfully created' % (newItem.name))
            return redirect(url_for('showItems',
                                    category_id=request.form['category_id']))
        else:
            flash("You're not allowed to create a new item")
            return redirect(url_for('showCategories'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newItem.html',
                               categories=categories,
                               username=login_session.get('username'))


@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
@login_is_required
def editItem(item_id):
    """
    Render page for editing an item and process editing in database
    Args:
        item_id (integer): id of item in question
    Returns:
        Rendered template of page to edit an item if GET request,
        processing of submitted data to edit if POST request
    """
    editedItem = session.query(Item).filter_by(id=item_id).one_or_none()
    if editedItem:
        if editedItem.category_id is not None:
            category = (session.query(Category)
                        .filter_by(id=editedItem.category_id).one_or_none())
        else:
            category = None
        if request.method == 'POST':
            if ((login_session.get('user_id') is not None) and
               (editedItem.user_id == login_session['user_id'])):
                if request.form['name']:
                    editedItem.name = request.form['name']
                if request.form['description']:
                    editedItem.description = request.form['description']
                if request.form['category_id']:
                    editedItem.category_id = request.form['category_id']
                session.add(editedItem)
                session.commit()
                flash('Item Successfully Edited')
                if category:
                    return redirect(url_for('showItems',
                                    category_id=category.id))
                else:
                    return redirect(url_for('showCategories'))
            else:
                flash("You're not allowed to edit this item!")
                if category:
                    return redirect(url_for('showItems',
                                    category_id=category.id))
                else:
                    return redirect(url_for('showCategories'))
        else:
            categories = session.query(Category).order_by(asc(Category.name))
            return render_template('editItem.html',
                                   categories=categories, item=editedItem,
                                   username=login_session.get('username'))
    else:
        flash('Item not found...')
        return redirect(url_for('showCategories'))


@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
@login_is_required
def deleteItem(item_id):
    """
    Render page for deleting an item and process deletion in database
    Args:
        item_id (integer): id of item in question
    Returns:
        Rendered template of page to delete an item if GET request,
        processing of submitted data to delete the item if POST request
    """
    itemToDelete = session.query(Item).filter_by(id=item_id).one_or_none()
    if itemToDelete:
        if itemToDelete.category_id is not None:
            category = (session.query(Category)
                        .filter_by(id=itemToDelete.category_id).one_or_none())
        else:
            catetgory = None
        if request.method == 'POST':
            if ((login_session.get('user_id') is not None) and
               (itemToDelete.user_id == login_session['user_id'])):
                session.delete(itemToDelete)
                session.commit()
                flash('Item Successfully Deleted')
                if category:
                    return redirect(url_for('showItems',
                                            category_id=category.id))
                else:
                    return redirect(url_for('showCategories'))
            else:
                flash("You're not allowed to edit this item!")
                if category:
                    return redirect(url_for('showItems',
                                            category_id=category.id))
                else:
                    return redirect(url_for('showCategories'))
        else:
            return render_template('deleteItem.html', item=itemToDelete,
                                   username=login_session.get('username'))
    else:
        flash('Item not found...')
        return redirect(url_for('showCategories'))


@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    """
    Render login page and process login request in database and user_session
    (internal password control) in database and user_session. The rendered
    page also shows external OAuth possibilities (Google and Facebook)
    Args:
        -
    Returns:
        Rendered template of login page if GET request, password control if
        POST request
    """
    if request.method == 'POST':
        userID = getUserID(request.form['email'])
        if userID:
            currentUser = getUserInfo(userID)
            if currentUser.verify_password(request.form['password']):
                flash('Login successful')
                login_session['username'] = currentUser.name
                login_session['email'] = currentUser.email
                login_session['user_id'] = currentUser.id
                return redirect(url_for('showCategories'))
            else:
                flash('Could not login')
                return redirect(url_for('showLogin'))
        else:
            flash('Could not login')
            return redirect(url_for('showLogin'))
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Render signup page lined to databse (no external OAuth)
    Args:
        -
    Returns:
        Rendered template of signup page if GET request, creation of new user
        if POST request
    """
    if request.method == 'POST':
        newUsername = request.form['username']
        newMail = request.form['mail']
        newPassword = request.form['password']
        # check if e-mail already exists
        existing_user = session.query(User).filter_by(email=newMail).first()
        if existing_user:
            flash("User already exists!")
            return redirect(url_for('showLogin'))
        # Create user
        # More checks are needed: password security , non-empty checks, etc.
        newUser = User(name=newUsername, email=newMail)
        newUser.hash_password(newPassword)
        session.add(newUser)
        session.commit()
        flash('New user successfully created')
        return redirect(url_for('showLogin'))
    else:
        return render_template('signup.html')


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Process login using Google's OAuth service
    Args:
        -
    Returns:
        If authorization successful, user session is linked to Google account
        of user who requested login. New user is created if first time login
    """
    # Security and authorization checks, stop if not successful
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('/var/www/CatalogApp/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json
                                 .dumps('Failed to upgrade the authorization '
                                        'code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json
                                 .dumps("Token's user ID doesn't match given "
                                        "use ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token client ID does not match"),
                                 401)
        print("Token client's ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        print('Already connected')
        response = make_response(json.dumps('Current user is already '
                                            'connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # Successful, make login_session referring to user who sent request
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    if getUserID(login_session['email']) is None:
        createuser(login_session)
    login_session['user_id'] = getUserID(login_session['email'])

    output = ''
    output += '</br>'
    output += '<h1> Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height/ 100px; border-radius: 50px;'
    output += '-webkit-border-radius: 50px; -moz-border-radius: 50px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    Process login using Facebook's OAuth service
    Args:
        -
    Returns:
        If authorization successful, user session is linked to FB account
        of user who requested login. New user is created if first time login
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s" % access_token)

    app_id = (json.loads(open('/var/www/CatalogApp/catalog/fb_client_secrets.json', 'r')
                         .read())['web']['app_id'])
    app_secret = (json.loads(open('/var/www/CatalogApp/catalog/fb_client_secrets.json', 'r')
                             .read())['web']['app_secret'])
    url = ('https://graph.facebook.com/v2.11/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    token = data['access_token']

    url = ('https://graph.facebook.com/v2.11/me?access_token=%s'
           '&fields=name,id,email' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    login_session['access_token'] = token

    url = ('https://graph.facebook.com/v2.11/me/picture?access_token=%s'
           '&redirect=0&height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createuser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 150px; height: 150px;'
    output += 'border-radius: 50px;'
    output += '-webkit-border-radius:50px; -moz-border-radius: 50px;">'
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route("/logout")
def logout():
    """
    Process logout
    Args:
        -
    Returns:
        If internal login, logout (deletion of login_session) and redirect,
        if external (Google, FB) redirect to respective logout procedures
    """
    if login_session.get('provider') is not None:
        if login_session['provider'] == 'google':
            return redirect(url_for('gdisconnect'))
        elif login_session['provider'] == 'facebook':
            return redirect(url_for('fbdisconnect'))
    else:
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        flash('You have been logged out')
        return redirect(url_for('showCategories'))


@app.route("/gdisconnect")
def gdisconnect():
    """
    Process logout for Google connected users
    Args:
        -
    Returns:
        Deletes login_session for Google connected user
    """
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['gplus_id']
        del login_session['credentials']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been logged out")
        response = make_response(json.dumps('Successfully disconnected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showCategories'))

    else:
        response = make_response(json.dumps('Failed to revoke token for '
                                            'given use.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbdisconnect')
def fbdisconnect():
    """
    Process logout for Facebook connected users
    Args:
        -
    Returns:
        Deletes login_session for Facebook connected user
    """
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s'
           % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['provider']
    del login_session['facebook_id']
    flash("You have been logged out")
    return redirect(url_for('showCategories'))


def createuser(login_session):
    """
    Create a new user in the database (no checks on duplicates)
    Args:
        -
    Returns:
        Id of newly created user, none if no result
    """
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = (session.query(User)
                   .filter_by(email=login_session['email']).one_or_none())
    if user:
        return user.id
    else:
        return None


def getUserInfo(user_id):
    """
    Query user in database with id 'user_id'
    Args:
        user_id (integer)
    Returns:
       User query in database of user with respective id, none if no result
    """
    user = session.query(User).filter_by(id=user_id).one_or_none()
    if user:
        return user
    else:
        return None


def getUserID(email):
    """
    Get user_id based on email input
    Args:
        email (string)
    Returns:
       user_id of user with respsective email, none if no result
    """
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        if user:
            return user.id
        else:
            return None
    except:
        return None


@auth.verify_password
def verify_password(email, password):
    """
    Verify password or login token for JSON requests
    Args:
        email (string)
        password (string)
    Returns:
       True if verification ok, else false
    """
    user_id = User.verify_auth_token(email)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one_or_none()
    else:
        user = session.query(User).filter_by(email=email).first()
        if not user or not user.verify_password(password):
            return False
    if user:
        g.user = user
        return True
    else:
        return False


@app.route('/token')
@auth.login_required
def get_auth_token():
    """
    Request on authorization token for JSON requests (so that no more,
    password, email combination is needed for 10 minutes). Identification
    is required
    Args:
        -
    Returns:
       JSON output with authorization token
    """
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    """
    Request JSON output of items in a category
    Args:
        category_id (integer)
    Returns:
       JSON output with item fields serialized
    """
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/new/JSON', methods=['POST'])
@auth.login_required
def newCategoryJSON():
    """
    Create a new category in POST request with JSON input
    Args:
        -
    Returns:
       JSON output mentioning the success of the operation
    """
    newCategoryName = request.json.get('newCategory')
    newCategory = Category(name=newCategoryName, user_id=g.user.id)
    session.add(newCategory)
    session.commit()
    return jsonify({'data': 'category successfully added'})


# @app.route('/users/JSON')
# def getUsers():
#     """
#     Request on information of all users in database (no administrator login
#     required forn now)
#     Args:
#         -
#     Returns:
#        JSON output with information about all users
#     """
#     users = session.query(User).all()
#     return jsonify(Users=[i.serialize for i in users])


# @app.route('/user/<email>/JSON')
# def getUser(email):
#     """
#     Request on information of one user in database (no administrator login
#     required forn now)
#     Args:
#         email (string)
#     Returns:
#        JSON output with information about the user in question
#     """
#     users = session.query(User).filter_by(email=email).first()
#     return jsonify(users.serialize)

app.secret_key = 'super_secret_key'
if __name__ == '__main__':
    #app.secret_key = 'super_secret_key'
    app.debug = True
    # app.run(host='0.0.0.0', port=80)
    app.run()
