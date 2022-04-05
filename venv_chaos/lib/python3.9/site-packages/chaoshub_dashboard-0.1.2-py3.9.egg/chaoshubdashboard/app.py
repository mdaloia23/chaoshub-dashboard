# -*- coding: utf-8 -*-
import logging
import logging.handlers
import os
import re
import string
import sys
from typing import Any, Callable, Dict, List

import cherrypy
from dotenv import load_dotenv
from flask import abort, Blueprint, current_app, Flask, request, url_for
from flask_caching import Cache
from flask_talisman import Talisman, GOOGLE_CSP_POLICY
from requestlogger import ApacheFormatter, WSGILogger
import shortuuid

from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, Date, Integer, String
from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy import event
from sqlalchemy.event import listens_for
from sqlalchemy.pool import Pool

from flask_sqlalchemy import SQLAlchemy

from sqlalchemy.engine import Engine
from sqlalchemy_utils import force_auto_coercion
# from werkzeug.contrib.fixers import ProxyFix
from werkzeug.middleware.proxy_fix import ProxyFix

from chaoshubdashboard.api.app import setup_service as setup_api
from chaoshubdashboard.auth.app import setup_service as setup_auth
from chaoshubdashboard.dashboard.app import setup_service as setup_dashboard
from chaoshubdashboard.experiment.app import setup_service as setup_experiment
from chaoshubdashboard.experiment.scheduler import register_schedulers, \
    shutdown_schedulers

from chaoshubdashboard.experiment.model import Discovery, Init, Experiment, Execution

from .model import db, get_db_conn_uri_from_env
from .settings import configure_app
from .utils import cache

## from .experiment import model
# from .experiment.views import execution
# from .auth.model import Account, LocalAccount, AccessToken, Client, ProviderToken
# from .auth.model import db
### from .auth.model import LocalAccount
## from .auth.model import db
# from .auth import views

__all__ = ["create_app", "cleanup_app"]


def create_app(create_tables: bool = False) -> Flask:
    """
    Create the application and its dependencies.
    """
    shortuuid.set_alphabet(string.ascii_lowercase + string.digits)
    app = Flask(__name__)

    configure_app(app)
    setup_cache(app)
    setup_app_logging(app)
    serve_static(app)
    serve_services(app, cache)
    setup_db(app, create_all=create_tables)
    setup_basic_security(app)
    setup_experiment_execution_schedulers(app)

    return app


def cleanup_app():
    """
    Cleanup the application. Usually call this before terminating the process.
    """
    shutdown_schedulers()


###############################################################################
# Internals
###############################################################################
def serve_services(app: Flask, cache: Cache):
    """
    Mount the application so it can served by the HTTP server.
    """
    setup_auth(app, cache)
    setup_dashboard(app, cache)
    setup_experiment(app, cache)
    setup_api(app, cache)

    # this will log requests to stdout
    app.wsgi_app = ProxyFix(app.wsgi_app)
    wsgiapp = WSGILogger(
        app.wsgi_app, [logging.StreamHandler()], ApacheFormatter(),
        propagate=False)
    cherrypy.tree.graft(wsgiapp, "/")


def setup_cache(app: Flask):
    """
    Initialize the application's cache.
    """
    cache.init_app(app)


def serve_static(app: Flask):
    """
    Create an app that is responsible to serve static resources.
    """
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    ui_dir = app.config.get("UI_ASSETS_DIR", "")

    # did we gete a specific location?
    if not ui_dir and not os.path.isdir(ui_dir):
        # maybe its an installed with the chaoshubdashboard package?
        ui_dir = os.path.join(cur_dir, 'ui')

    # assume development mode
    if not ui_dir or not os.path.isdir(ui_dir):
        ui_dir = os.path.join(cur_dir, '..', '..', 'ui', 'dist')

    if not os.path.isdir(ui_dir):
        raise RuntimeError(
            "Cannot find your static resources (html, img, css...). "
            "Please set the UI_ASSETS_DIR environment variable to point "
            "where they are located.")

    app.logger.info("Serving static files from {}".format(ui_dir))
    app.template_folder = ui_dir
    cherrypy.tree.mount(None, "/static", {
        "/": {
            "tools.staticdir.on": True,
            "tools.staticdir.dir": os.path.join(ui_dir, 'static')
        }
    })


def setup_app_logging(app: Flask):
    """
    Create a logger for the application itself.
    """
    fmt = logging.Formatter(
        '[%(asctime)s] %(levelname)s %(module)s: %(message)s',
        datefmt='%d/%b/%Y:%H:%M:%S')
    app.logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(fmt)
    app.logger.addHandler(handler)


def setup_db(app: Flask, create_all: bool = False):

    """
    Initialize our database connection.
    """

    app.config["SQLALCHEMY_ECHO"] = True if os.getenv("DB_DEBUG") else False
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    conn_uri = get_db_conn_uri_from_env()
    print(f"Connection String: {conn_uri}")
    app.config["SQLALCHEMY_DATABASE_URI"] = conn_uri
    app.config["SQLALCHEMY_BINDS"] = {
        'dashboard_service': conn_uri,
        'experiment_service': conn_uri,
        'auth_service': conn_uri,
        'api_service': conn_uri
    }

    # let sqlalchemy utils help us converting data in/out of the database
    force_auto_coercion()

    # Need this in order for DBAPI connection to be established
    # New DBAPI connection: <sqlite3.Connection object at 0x107bd8d50>
    # Connection record: <sqlalchemy.pool.base._ConnectionRecord object at 0x107cdfdf0>
    ## db = SQLAlchemy(app)
    
    ####################
    if conn_uri.startswith('sqlite'):
        db_file = re.sub("sqlite.*:///", "", conn_uri)
        print(f"DB file={db_file}")
        try:
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
        except Exception as e:
            print(f"Exception: {e}")

        @listens_for(Pool, "connect", named=True)
        def on_connect(dbapi_connection, **kw):
            print("New DBAPI connection:", dbapi_connection)
            print("Connection record:", kw['connection_record'])

            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    db.init_app(app)

    with app.app_context():
            
        try:
            from .users.model import User
            from .experiment.model import Execution, Experiment
            from .auth.model import Client, ProviderToken, AccessToken, Account, LocalAccount
        except Exception as e:
            print(f"import exception: {e}")

        # table User gets created
        '''
        class User(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(80), unique=True)

            def __repr__(self):
                return '<User %r>' % self.username
        '''

        ## db.init_app(app)
        if create_all:
            try:
                # db.create_all(app=app)
                #### db.create_all()
                db.create_all(app=app)
                ## db.session.commit()
            except Exception as e:
                print(f"Exception when create_all is called: {e}")
            
            print(f"Database created successfully")
            # if db.engine.has_table('local_account'):
            if db.engine.table_names():
                print(f"Database has tables")
            else:
                print(f"Database is missing tables")
                sys.exit(1)

    ## engine = create_engine(conn_uri)

    # engine = create_engine('sqlite:///\\sqlitedbs\\chaoshub.db', echo=True)
    ## Base = declarative_base()
    ## Base.metadata.create_all(engine)

    ## db.create_all(app=app)
    ####################


'''

def setup_db(app: Flask, create_all: bool = False):
    """
    Initialize our database connection.
    """
    app.config["SQLALCHEMY_ECHO"] = True if os.getenv("DB_DEBUG") else False
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    conn_uri = get_db_conn_uri_from_env()
    app.config["SQLALCHEMY_DATABASE_URI"] = conn_uri
    app.config["SQLALCHEMY_BINDS"] = {
        'dashboard_service': conn_uri,
        'experiment_service': conn_uri,
        'auth_service': conn_uri,
        'api_service': conn_uri
    }

    # let sqlalchemy utils help us converting data in/out of the database
    force_auto_coercion()

    # when running SQLite, we must enable this directive on each new
    # connexion made to the database to enable foreign key relationships
    if conn_uri.startswith("sqlite"):
        @listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    with app.app_context():
        db.init_app(app)
        if create_all:
            db.create_all(app=app)

'''

def setup_basic_security(app: Flask):
    """
    Apply some basic security specifications over the HTTP exchanges.
    """
    csp = GOOGLE_CSP_POLICY.copy()

    csp["style-src"] = csp["style-src"].split(' ')
    csp["style-src"].append("*.fontawesome.com")
    csp["style-src"].append("*.cloudflare.com")
    csp["style-src"].append("'unsafe-inline'")

    csp["font-src"] = csp["font-src"].split(' ')
    csp["font-src"].append("*.fontawesome.com")
    csp["font-src"].append("'unsafe-inline'")

    csp["default-src"] = csp["default-src"].split(' ')
    # csp["default-src"].append("'self'")

    csp["img-src"] = []
    csp["img-src"].append("'self'")

    Talisman(
        app, force_https=False, strict_transport_security=False,
        session_cookie_secure=False, content_security_policy=csp
    )


def setup_experiment_execution_schedulers(app: Flask):
    """
    Register all installed schedulers
    """
    schedulers = register_schedulers(app.config)
    for name in schedulers:
        app.logger.info("Registered '{}' scheduler".format(name))
