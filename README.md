# Catalog Application

## About
This project entails a Python-based web application which allows users to create, read, update and delete their own categories and corresponding items.

All items and categories are publicly visible for all users, even if not logged-in. The homepage is at: http://localhost:5000/
Once logged-in, users can create any item and any category and they can assign any existing category to their items.
Update and delete functionality for categories and items is only allowed for the creators (once logged in).
When a category is deleted by the creator, all items belonging to this category are deleted as well, even items created by a different user than the category creator.

Users can login by first signing up, or by using authorization through Google or Facebook.
Functionality for retrieving forgotten passwords has not yet been implemented.

Several JSON-endpoints have been implemented:
* http://localhost:5000/users/JSON (GET): retrieving user information for all registered users (publicly accessible for everyone).
* http://localhost:5000/user/<email>/JSON (GET): retrieving user information for one particular user with specified email (publicly accessible for everyone).
* http://localhost:5000/category/new/JSON (POST): creating a new category, authentication required.
* http://localhost:5000/category/<int: category_id>/JSON (GET): retrieving all objects in a specific category (publicly accessible for everyone).
* http://localhost:5000/token (GET): retrieving a 10-minute valid access token, authentication required.

Authors: Cedric Faché
Login page credentials: https://bootsnipp.com
For any questions or to submit bugs, please refer to http://www.udacity.com
This is an updated version after an initial review from a Udacity instructor.
For all licening information, please refer to a responsible at http://www.udacity.com

## Contents
This package contains:

* Python main-file (minimally requierd): project.py.
* Python database setup file (minimally required): database_setup.py
* HTML templates in the folder 'templates' for generating web-pages (minimally required)
* CSS styles in the folder 'static' (strongly required for streamlined layout)
* OAuth2-login details: 'client_secrets.json' and 'fb_client_secrets.json' (required for OAuth2 Login through Google and Facebook respectively)
* Other files: 'catalog_application.db', 'database_setup.pyc' are initialized with dummy data. A blank database can be generated by removing these files and running the 'database_setup.py' file in the terminal.

## Requirements
Following must be installed:

* Python 3.6.2: please follow guidelines on https://www.python.org
* SQLite: please follow guidelines on https://www.sqlite.org . A Ubuntu virtual environment might be needed. In that case, VirtualBox (https://www.virtualbox.org) is recommended.

## Setting up the database and running the server

* (Optional) Initialize the database from scratch by removing 'catalog_application.db' and 'database_setup.pyc'. Use the terminal to cd into the packages directory and run 'python database_setup.py' to set up a blank database.
* Run the server: use the terminal to cd into the packages directory and run 'python project.py'. The server will run on 'http://localhost:5000/'
* The application can be accessed locally through any webbrowser at port 5000 (http://localhost:5000/)