import sys
import os
from itertools import groupby

# Monkey patch flask._compat for Flask-Script
from metabomatch import _compat
sys.modules['flask._compat'] = _compat

# Monkey patch jinja2.Markup for old libraries
import jinja2
import markupsafe
jinja2.Markup = markupsafe.Markup

# Monkey patch werkzeug.urls.url_quote for flask-oauthlib
import werkzeug.urls
import urllib.parse
werkzeug.urls.url_quote = urllib.parse.quote
werkzeug.urls.url_decode = urllib.parse.parse_qs
werkzeug.urls.url_encode = urllib.parse.urlencode

import inspect
import collections
if not hasattr(inspect, "getargspec"):
    ArgSpec = collections.namedtuple("ArgSpec", "args varargs keywords defaults")
    def getargspec(func):
        spec = inspect.getfullargspec(func)
        return ArgSpec(spec.args, spec.varargs, spec.varkw, spec.defaults)
    inspect.getargspec = getargspec

from flask import current_app
import flask
from werkzeug.local import LocalStack
if not hasattr(flask, '_request_ctx_stack'):
    flask._request_ctx_stack = LocalStack()
if not hasattr(flask, '_app_ctx_stack'):
    flask._app_ctx_stack = LocalStack()

try:
    from metabomatch.private_keys import GUEST_USER_ID
except ImportError:
    GUEST_USER_ID = os.environ.get('GUEST_USER_ID')

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError
from flask_script import (Manager, Shell, Server, prompt, prompt_pass,
                              prompt_bool)
# from flask_migrate import MigrateCommand

from metabomatch.softwares.models import Software, SentenceSoftwareMapping, Sentence, \
    get_nb_commits, Upvote, ProConsUpvote, ProCons

from metabomatch.app import create_app
from metabomatch.extensions import db
from metabomatch.flaskbb.utils.populate import (create_test_data, create_welcome_forum,
                                                create_admin_user, create_default_groups, create_default_settings)

# Use the development configuration if available
try:
    from metabomatch.configs.development import DevelopmentConfig as Config
except ImportError:
    from metabomatch.configs.default import DefaultConfig as Config

flask_app = create_app(Config)
manager = Manager(flask_app)

# Run local server
manager.add_command("runserver", Server("localhost", port=5000))

# Migration commands
# manager.add_command('db', MigrateCommand)


# Add interactive project shell
def make_shell_context():
    return dict(app=current_app, db=db)
manager.add_command("shell", Shell(make_context=make_shell_context))


@manager.command
def initdb():
    """Creates the database."""
    db.create_all()


@manager.command
def dropdb():
    """Deletes the database"""
    db.drop_all()


@manager.command
def createall(dropdb=False, createdb=False):
    """Creates the database with some testing content.
    If you do not want to drop or create the db add
    '-c' (to not create the db) and '-d' (to not drop the db)
    """
    if not dropdb:
        flask_app.logger.info("Dropping database...")
        db.drop_all()

    if not createdb:
        flask_app.logger.info("Creating database...")
        db.create_all()

    flask_app.logger.info("Creating test data...")
    create_test_data()


@manager.option('-u', '--username', dest='username')
@manager.option('-p', '--password', dest='password')
@manager.option('-e', '--email', dest='email')
def create_admin(username=None, password=None, email=None):
    if not (username and password and email):
        username = prompt("Username")
        email = prompt("A valid email address")
        password = prompt_pass("Password")

    create_admin_user(username=username, password=password, email=email)


@manager.option('-u', '--username', dest='username')
@manager.option('-p', '--password', dest='password')
@manager.option('-e', '--email', dest='email')
def initflaskbb(username=None, password=None, email=None):
    """Initializes FlaskBB with all necessary data"""
    flask_app.logger.info("Creating default data...")
    try:
        create_default_groups()
        create_default_settings()
    except IntegrityError:
        flask_app.logger.error("Couldn't create the default data because it already "
                               "exist!")
        if prompt_bool("Do you want to recreate the database? (y/n)"):
            db.session.rollback()
            db.drop_all()
            db.create_all()
            create_default_groups()
            create_default_settings()
        else:
            sys.exit(0)
    except OperationalError:
        flask_app.logger.error("No database found.")
        if prompt_bool("Do you want to create the database now? (y/n)"):
            db.session.rollback()
            db.create_all()
            create_default_groups()
            create_default_settings()
        else:
            sys.exit(0)

    flask_app.logger.info("Creating admin user...")
    if username and password and email:
        create_admin_user(username=username, password=password, email=email)
    else:
        create_admin()

    flask_app.logger.info("Creating welcome forum...")
    create_welcome_forum()

    flask_app.logger.info(
        "Congratulations! FlaskBB has been successfully installed")


@manager.command
def update_softwares_rates():
    softwares = Software.query.all()
    for i in range(2):
        for s in softwares:
            s.populate()

    Software.set_rankings(softwares)


@manager.command
def init_rankings():
    Software.set_rankings()


@manager.command
def fix_upvotes():
    sentence_soft_map = SentenceSoftwareMapping.query.all()
    for o in sentence_soft_map:
        if o.software.name in ('Proteowizard', 'Rdisop'):
            o.upvote -= 1
            o.save()

            # upvotes = Upvote.query.all()
            # for key, group in groupby(upvotes, key=lambda _: _.sentence_software_mapping.software_id):
            #     up = set(group)
            #     i = 0
            #     if key in ('Proteowizard', 'Rdisop'):
            #         for u in up:
            #             if u.user_id == GUEST_USER_ID:
            #                 u.delete()
            #             break

            # to_break = False
        # while i < 3 and not to_break:
        #     for u in up:
        #         if u.user_id == GUEST_USER_ID:
        #             u.delete()
        #             up.remove(u)
        #             i += 1
        #             break
        #     if GUEST_USER_ID not in {u.user_id for u in up}:
        #         to_break = True


@manager.command
def reset_upvotes():
    sentence_soft_map = SentenceSoftwareMapping.query.all()
    for o in sentence_soft_map:
        o.upvote = 0
        o.save()
    upvotes = Upvote.query.all()
    for u in upvotes:
        u.delete()


@manager.command
def fix_procon_upvote():
    procon_upvote = ProCons.query.all()
    for p in procon_upvote:
        if p.software_name == 'Proteowizard':
            p.kind = 'pro'
            p.save()


if __name__ == "__main__":
    manager.run()
