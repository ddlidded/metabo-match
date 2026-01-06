# -*- coding: utf-8 -*-
"""
    auth.views
    This view provides user authentication, registration and a view for
    resetting the password of a user if he has lost his password

"""

import os
import datetime
import requests

from flask import Blueprint, flash, redirect, url_for, request, current_app, session
from flask_login import current_user, login_user, login_required, logout_user, confirm_login, login_fresh

from metabomatch.extensions import github, oauth
from metabomatch.flaskbb.utils.helpers import render_template
from metabomatch.email import send_reset_token
from metabomatch.auth.forms import LoginForm, ReauthForm, ForgotPasswordForm, ResetPasswordForm
from metabomatch.user.models import User

try:
    from metabomatch.private_keys import TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET
except ImportError:
    TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET = None, None

try:
    from metabomatch.private_keys import (
        AUTHENTIK_CLIENT_ID,
        AUTHENTIK_CLIENT_SECRET,
        AUTHENTIK_AUTHORIZE_URL,
        AUTHENTIK_ACCESS_TOKEN_URL,
        AUTHENTIK_USERINFO_URL,
        AUTHENTIK_SCOPE,
    )
except ImportError:
    AUTHENTIK_CLIENT_ID = os.environ.get("AUTHENTIK_CLIENT_ID")
    AUTHENTIK_CLIENT_SECRET = os.environ.get("AUTHENTIK_CLIENT_SECRET")
    AUTHENTIK_AUTHORIZE_URL = os.environ.get("AUTHENTIK_AUTHORIZE_URL")
    AUTHENTIK_ACCESS_TOKEN_URL = os.environ.get("AUTHENTIK_ACCESS_TOKEN_URL")
    AUTHENTIK_USERINFO_URL = os.environ.get("AUTHENTIK_USERINFO_URL")
    AUTHENTIK_SCOPE = os.environ.get("AUTHENTIK_SCOPE", "openid email profile")

auth = Blueprint("auth", __name__)


# Use Twitter as example remote application
twitter_key = TWITTER_CONSUMER_KEY or os.environ.get('TWITTER_CONSUMER_KEY')
twitter_secret = TWITTER_CONSUMER_SECRET or os.environ.get('TWITTER_CONSUMER_SECRET')
if twitter_key and twitter_secret:
    twitter = oauth.remote_app('twitter',
                               base_url='https://api.twitter.com/1.1/',
                               request_token_url='https://api.twitter.com/oauth/request_token',
                               access_token_url='https://api.twitter.com/oauth/access_token',
                               authorize_url='https://api.twitter.com/oauth/authenticate',
                               consumer_key=twitter_key,
                               consumer_secret=twitter_secret)
else:
    twitter = None

if all([AUTHENTIK_CLIENT_ID, AUTHENTIK_CLIENT_SECRET, AUTHENTIK_AUTHORIZE_URL, AUTHENTIK_ACCESS_TOKEN_URL]):
    authentik = oauth.remote_app(
        'authentik',
        consumer_key=AUTHENTIK_CLIENT_ID,
        consumer_secret=AUTHENTIK_CLIENT_SECRET,
        request_token_params={'scope': AUTHENTIK_SCOPE},
        base_url='',
        access_token_url=AUTHENTIK_ACCESS_TOKEN_URL,
        access_token_method='POST',
        authorize_url=AUTHENTIK_AUTHORIZE_URL,
    )
else:
    authentik = None

@auth.route("/login", methods=["GET"])
def login():
    """
    Logs the user in
    """

    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for("user.profile"))

    # form = LoginForm(request.form)
    # if form.validate_on_submit():
    #     user, authenticated = User.authenticate(form.login.data,
    #                                             form.password.data)
    #
    #     if user and authenticated:
    #         # remove this key when a user is authenticated
    #         session.pop('nb_views', None)
    #         login_user(user, remember=form.remember_me.data)
    #         return redirect(request.args.get("next") or url_for("softwares.index"))

        # flash("Wrong username or password", "danger")
    return render_template("auth/login.html")  # , form=form)


@auth.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    """
    Reauthenticates a user
    """

    if not login_fresh():
        form = ReauthForm(request.form)
        if form.validate_on_submit():
            confirm_login()
            flash("Reauthenticated", "success")
            return redirect(request.args.get("next") or
                            url_for("user.profile"))
        return render_template("auth/reauth.html", form=form)
    return redirect(request.args.get("next") or
                    url_for("user.profile", username=current_user.username))


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "success")
    return redirect(url_for("softwares.index"))


@auth.route("/register", methods=["GET", "POST"])
def register():
    """
    Register a new user
    """

    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for("user.profile"))

    if current_app.config["RECAPTCHA_ENABLED"]:
        from metabomatch.auth.forms import RegisterRecaptchaForm
        form = RegisterRecaptchaForm(request.form)
    else:
        from metabomatch.auth.forms import RegisterForm
        form = RegisterForm(request.form)

    if form.validate_on_submit():
        user = form.save()
        login_user(user)

        flash("Thanks for registering", "success")
        return redirect(url_for("user.profile", username=current_user.username))
    return render_template("auth/register.html", form=form)


@auth.route('/resetpassword', methods=["GET", "POST"])
def forgot_password():
    """
    Sends a reset password token to the user.
    """

    if not current_user.is_anonymous:
        return redirect(url_for("forum.index"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            token = user.make_reset_token()
            send_reset_token(user, token=token)

            flash("E-Mail sent! Please check your inbox.", "info")
            return redirect(url_for("auth.forgot_password"))
        else:
            flash(("You have entered an username or email that is not linked \
                with your account"), "danger")
    return render_template("auth/forgot_password.html", form=form)


@auth.route("/resetpassword/<token>", methods=["GET", "POST"])
def reset_password(token):
    """
    Handles the reset password process.
    """

    if not current_user.is_anonymous:
        return redirect(url_for("forum.index"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        expired, invalid, data = user.verify_reset_token(form.token.data)

        if invalid:
            flash("Your password token is invalid.", "danger")
            return redirect(url_for("auth.forgot_password"))

        if expired:
            flash("Your password is expired.", "danger")
            return redirect(url_for("auth.forgot_password"))

        if user and data:
            user.password = form.password.data
            user.save()
            flash("Your password has been updated.", "success")
            return redirect(url_for("auth.login"))

    form.token.data = token
    return render_template("auth/reset_password.html", form=form)


@auth.route("/login_github")
def login_github():
    """
    github authentication
    """
    
    callback_url = url_for('auth.authorized', next=request.args.get('next'))
    return github.authorize()  
    # got serious problem when specifying a callback url
    # redirect_uri=callback_url)


# authentik authentication
@auth.route('/login_authentik')
def login_authentik():
    if authentik is None:
        flash("Authentik login is not configured.", "warning")
        return redirect(url_for("softwares.index"))
    callback_url = url_for('auth.authentik_authorized', next=request.args.get('next'), _external=True)
    return authentik.authorize(callback=callback_url or request.referrer or None)


# authentik callback oauth
@auth.route('/authentik-authorized')
def authentik_authorized():
    if authentik is None:
        flash("Authentik login is not configured.", "warning")
        return redirect(url_for("softwares.index"))
    next_url = request.args.get('next') or url_for('softwares.index')
    resp = authentik.authorized_response()
    if resp is None or 'access_token' not in resp:
        flash('Authentik login failed.', 'danger')
        return redirect(url_for('softwares.index'))
    access_token = resp['access_token']
    userinfo_url = AUTHENTIK_USERINFO_URL
    try:
        userinfo = requests.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception:
        userinfo = {}
    username = userinfo.get('preferred_username') or userinfo.get('name') or userinfo.get('email') or 'user'
    email = userinfo.get('email') or f"{username}@example.com"
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User()
        user.username = username
        user.email = email
        user.password = 'oauth'
        user.primary_group_id = 4
        user.date_joined = datetime.datetime.utcnow()
        user = user.save()
    login_user(user, True)
    flash("Authentik login succeeded.", "success")
    return redirect(next_url)


# twitter authentication
@auth.route('/login_twitter')
def login_twitter():
    """
    twitter authentication
    """
    if twitter is None:
        flash("Twitter login is not configured.", "warning")
        return redirect(url_for("softwares.index"))
    callback_url = url_for('auth.twitter_authorized', next=request.args.get('next'))
    return twitter.authorize(callback=callback_url or request.referrer or None)


@auth.route('/twitter-authorized')
def twitter_authorized():
    """
    twitter callback oauth
    """
    if twitter is None:
        flash("Twitter login is not configured.", "warning")
        return redirect(url_for("softwares.index"))

    next_url = request.args.get('next') or url_for('softwares.index')

    resp = twitter.authorized_response()
    if resp is None:
        flash('Twitter login failed !', 'danger')
        return redirect(url_for('softwares.index'))

    user = User.query.filter(User.username == resp['screen_name']).first()
    if user is None:
        user = User.create_from_twitter_oauth(resp)

    login_user(user, True)
    flash("Twitter login succeeded.", "success")
    return redirect(next_url)


@auth.route('/github-callback')
@github.authorized_handler
def authorized(oauth_token):
    """
    github callback oauth
    """

    next_url = request.args.get('next') or url_for('softwares.index')
    if oauth_token is None:
        flash("Github login failed.", "danger")
        return redirect(url_for('softwares.index'))

    user = User.query.filter_by(github_access_token=oauth_token).first()
    if user is None:
        user = User.create_github_account(oauth_token)

    # session.pop('nb_views', None)
    # force remembering
    login_user(user, True)
    flash("Github login succeeded.", "success")

    return redirect(next_url)


@github.access_token_getter
def token_getter():
    u = User.query.filter(User.id == 1).first()
    return u.github_access_token


if twitter is not None:
    @twitter.tokengetter
    def get_twitter_token(token=None):
        if current_user.is_authenticated and current_user.twitter_access_token is not None:
            return current_user.twitter_access_token, current_user.twitter_secret_token
