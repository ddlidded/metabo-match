# -*- coding:utf-8 -*-
"""
Software views
"""

from datetime import datetime, timedelta
from itertools import groupby
from collections import OrderedDict
import json
from metabomatch.user.models import User
import os

from jinja2 import Template

from metabomatch.news.models import Article
from metabomatch.scripts.models import Script

try:
    from metabomatch.private_keys import GUEST_USER_ID
except ImportError:
    GUEST_USER_ID = os.environ.get('GUEST_USER_ID')

from sqlalchemy import desc, func, asc
from flask import Blueprint, request, redirect, url_for, flash, abort, render_template_string, jsonify

from flask_login import login_required, current_user
from flask_wtf import FlaskForm as Form
from flask_sqlalchemy.pagination import Pagination

from metabomatch.flaskbb.utils.helpers import crop_title, time_since
from metabomatch.achievements import SoftwareAchievement, SCORE_SOFT
from metabomatch.extensions import db, cache
from metabomatch.flaskbb.utils.helpers import render_template
from metabomatch.flaskbb.utils.permissions import is_admin
from metabomatch.softwares.models import Software, Tag, Comment, Rating, Sentence, SentenceSoftwareMapping, Upvote, \
    ProCons, ProConsUpvote
from metabomatch.softwares.forms import SoftwareForm, SoftwareUpdateForm, ProConsForm
from metabomatch.utils import s3_upload, s3_upload_from_server, s3_delete, mean, best_softs_by_cat


softwares = Blueprint("softwares", __name__, template_folder="../../templates")


SOFT_MAP = {'1': 'Signal Extraction',
            '2': 'LC Alignment',
            '3': 'Database Search',
            '4': 'Statistical Analysis'}


SOFT_PAR_PAGE = 10

TEMPLATE = """
            {% for kind, inst in activities %}
                <div class="alert alert-default" style="padding-top:0">
                    <div class="container" style="width:100%;">
                        <div class="col-md-1">
                            <span class="fa  {% if kind == 'comment' %} fa-comments-o {% elif kind == 'script' %} fa-code {% elif kind == 'rating' %} fa-certificate {% else %} fa-chevron-circle-up {% endif %} fa-2x text-muted"></span>
                        </div>
                        <div class="col-md-11">
                            <p></p>
                            {% if kind =='comment' %}
                                <p>
                                    <strong>
                                        <a href="{{ url_for('user.profile', username=inst.user.username) }}">
                                        {% if inst.user.avatar %}
                                            <img src="{{ inst.user.avatar }}" alt="Avatar" height="20" width="20"
                                                 data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% else %}
                                            <img src="{{ inst.user.email | gravatar }}" alt="gravatar"
                                                 height="20" width="20" data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% endif %}
                                        </a>
                                        posted a comment on <a
                                            href="{{ url_for('softwares.info', name=inst.software.name) }}">{{ inst.software.name }}</a>
                                        &bull;
                                        <em>{{ inst.date_created | time_since }}</em>
                                    </strong>
                                </p>
                                 <p>
                                    <small class=text-muted>{{ inst.content | crop_title(length=200) }}</small>
                                </p>

                            {% elif kind == 'script' %}
                                <p>
                                    <strong>
                                        <a href="{{ url_for('user.profile', username=inst.user.username) }}">
                                        {% if inst.user.avatar %}
                                            <img src="{{ inst.user.avatar }}" alt="Avatar" height="20" width="20"
                                                    data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% else %}
                                            <img src="{{ inst.user.email | gravatar }}" alt="gravatar"
                                                 height="20" width="20" data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% endif %}
                                        </a>
                                        just submit a <a
                                            href="{{ url_for('scripts.info', script_id=inst.id, slug=inst.slug) }}">new
                                        script</a>
                                        &bull;
                                        <em>{{ inst.creation_date | time_since }}</em>
                                    </strong>
                                </p>
                            {% elif kind == 'rating' %}
                                <p>
                                    <strong>
                                        <a href="{{ url_for('user.profile', username=inst.user.username) }}">
                                        {% if inst.user.avatar %}
                                            <img src="{{ inst.user.avatar }}" alt="Avatar" height="20" width="20"
                                                    data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}" >
                                        {% else %}
                                            <img src="{{ inst.user.email | gravatar }}" alt="gravatar"
                                                 height="20" width="20" data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% endif %}
                                        </a>
                                        gave <label class="label label-info" style="font-size: 1em;">{{ inst.rate }}</label>
                                        for <a
                                            href="{{ url_for('softwares.info', name=inst.software.name) }}">{{ inst.software.name }}</a>
                                        &bull;
                                        <em>{{ inst.date_created | time_since }}</em>
                                    </strong>
                                </p>
                            {% elif kind == 'procons_upvote' %}
                                <p>
                                    <strong>
                                        <a href="{{ url_for('user.profile', username=inst.user.username) }}">
                                            {% if inst.user.avatar %}
                                                <img src="{{ inst.user.avatar }}" alt="Avatar" height="20" width="20"
                                                     data-toggle="tooltip" data-placement="bottom"
                                                     title="{{ inst.user.username }}">
                                            {% else %}
                                                <img src="{{ inst.user.email | gravatar }}" alt="gravatar"
                                                     height="20" width="20" data-toggle="tooltip"
                                                     data-placement="bottom"
                                                     title="{{ inst.user.username }}">
                                            {% endif %}
                                        </a>
                                        upvoted a {{ inst.procons.kind }}: <a href="{{ url_for('softwares.info', name=inst.procons.software.name) }}">{{ inst.procons.title }}</a>
                                        &bull;
                                            <label class="label label-{% if inst.procons.kind == 'pro' %}success{% else %}danger{% endif %} ">
                                                {{ inst.procons.procons_upvotes | length }}
                                            </label> upvotes
                                        &bull;
                                        <em>{{ inst.upvote_date | time_since }}</em>
                                    </strong>
                                </p>
                                <p>
                                    <small class=text-muted>{{ inst.description | crop_title(length=200) }}</small>
                                </p>
                            {% else %}
                                <p>
                                    <strong>
                                        <a href="{{ url_for('user.profile', username=inst.user.username) }}">
                                        {% if inst.user.avatar %}
                                            <img src="{{ inst.user.avatar }}" alt="Avatar" height="20" width="20">
                                        {% else %}
                                            <img src="{{ inst.user.email | gravatar }}" alt="gravatar"
                                                 height="20" width="20" data-toggle="tooltip" data-placement="bottom"
                                                 title="{{inst.user.username}}">
                                        {% endif %}
                                        </a>
                                        upvoted
                                        <a href="{{ url_for('softwares.info', name=inst.sentence_software_mapping.software.name) }}">{{ inst.sentence_software_mapping.software.name }}
                                        </a>
                                        &bull;
                                        <em>{{ inst.date_created | time_since }}</em>
                                    </strong>
                                </p>
                            {% endif %}
                        </div>
                    </div>
                </div>
            {% endfor %}
            """


@softwares.route('/')
def index():
    """dealing with GET args"""

    page = request.args.get("page", 1, type=int)
    month = request.args.get('month', 1, type=int)
    sort_by_name = request.args.get('sort_name')
    sort_by_rate = request.args.get('sort_rate')
    if request.args.get('category') is not None:
        keyword = SOFT_MAP[request.args['category']]
        if sort_by_name is not None:
            softs = Software.query.join(Software.tags).filter(Tag.tag == keyword).order_by(asc(Software.name)).paginate(
                page=page, per_page=SOFT_PAR_PAGE, error_out=True)
        elif sort_by_rate is not None:
            softs = Software.query.join(Software.tags).filter(Tag.tag == keyword).all()
            softs = Pagination(None, page, SOFT_PAR_PAGE, len(softs),
                               sorted(softs, key=lambda _: _.compute_rate(), reverse=True))
        else:
            softs = Software.query.join(Software.tags).filter(Tag.tag == keyword).paginate(page=page, per_page=SOFT_PAR_PAGE, error_out=True)

    elif request.args.get('text') is not None:
        text = request.args['text']
        softs = Software.query.filter(Software.name.ilike('%' + text + '%')).paginate(page=page, per_page=SOFT_PAR_PAGE, error_out=True)
    else:
        if sort_by_name is not None:
            softs = Software.query.order_by(asc(Software.name)).paginate(page=page, per_page=SOFT_PAR_PAGE, error_out=True)
        elif sort_by_rate is not None:
            softs = sorted(Software.query.all(), key=lambda _: _.compute_rate(), reverse=True)
            p = (page - 1) * SOFT_PAR_PAGE
            next_p = p + SOFT_PAR_PAGE
            softs = Pagination(None, page, SOFT_PAR_PAGE, len(softs), softs[p:next_p])
        else:
            softs = Software.query.order_by(desc(Software.insertion_date)).paginate(page=page, per_page=SOFT_PAR_PAGE, error_out=True)

    # loading objects
    current_time = datetime.utcnow()
    month_ago = current_time - timedelta(weeks=month * 5)
    comment_insts = Comment.query.filter(Comment.date_created > month_ago).all()
    rating_insts = Rating.query.filter(Rating.date_created > month_ago).all()
    upvote_insts = Upvote.query.filter(Upvote.date_created > month_ago).all()
    script_insts = Script.query.filter(Script.creation_date > month_ago).all()
    procons_up_insts = ProConsUpvote.query.filter(ProConsUpvote.upvote_date > month_ago).all()

    # seems to be not used anymore
    # guest_user = User.query.filter(User.id == GUEST_USER_ID).first()

    upvotes_fixed = []
    for u in upvote_insts:
        # if u.user is None:
        #     u.user = guest_user
        #     u.save()
        u.date_created = datetime(u.date_created.year, u.date_created.month, u.date_created.day)
        upvotes_fixed.append(u)

    r = []

    def f(inst):
        if isinstance(inst, Comment) or isinstance(inst, Upvote) or isinstance(inst, Rating):
            return inst.date_created
        elif isinstance(inst, Script):
            return inst.creation_date
        elif isinstance(inst, ProConsUpvote):
            return inst.upvote_date

    sorted_insts = sorted(script_insts + comment_insts + rating_insts + upvotes_fixed + procons_up_insts,
                          key=f,
                          reverse=True)
    if sorted_insts:
        for x in sorted_insts:
            if isinstance(x, Comment):
                s = 'comment'
            elif isinstance(x, Rating):
                s = 'rating'
            elif isinstance(x, Script):
                s = 'script'
            elif isinstance(x, ProConsUpvote):
                s = 'procons_upvote'
            else:
                s = 'upvote'
            r.append((s, x))

    last_articles = Article.query.order_by(desc(Article.creation_date)).limit(10)

    return render_template('softwares/softwares.html',
                           softwares=softs,
                           activities=r,
                           last_articles=last_articles,
                           best_softwares=best_softs_by_cat(),
                           delta_rankings_ui=Software.pos_delta_upvotes(category='UI'),
                           delta_rankings_perf=Software.pos_delta_upvotes(category='PERFORMANCE'),
                           delta_rankings_support=Software.pos_delta_upvotes(category='SUPPORT'),
                           delta_rankings_global_rate=Software.pos_delta_by_global_rate(),
                           current_month=month,  # or could be accessible from the request object from template directly
                           today=datetime.now())


@softwares.route('/softwares/get-more-notifications')
def get_more_notifications():
    """
    supposed to be ajax retrieved
    :return:
    """
    month = int(request.args['month']) if 'month' in request.args else 1

    current_time = datetime.utcnow()
    month_datetime = current_time - timedelta(weeks=month * 5)

    next_month_datetime = month_datetime - timedelta(weeks=5)  # come back one month earlier

    comment_insts = Comment.query.filter(Comment.date_created < month_datetime,
                                         Comment.date_created > next_month_datetime).all()

    rating_insts = Rating.query.filter(Rating.date_created < month_datetime,
                                       Rating.date_created > next_month_datetime).all()

    upvote_insts = Upvote.query.filter(Upvote.date_created < month_datetime,
                                       Upvote.date_created > next_month_datetime).all()

    script_insts = Script.query.filter(Script.creation_date < month_datetime,
                                       Script.creation_date > next_month_datetime).all()

    upvotes_fixed = []
    for u in upvote_insts:
        # if u.user is None:
        #     u.user = guest_user
        #     u.save()
        u.date_created = datetime(u.date_created.year, u.date_created.month, u.date_created.day)
        upvotes_fixed.append(u)

    sorted_insts = sorted(script_insts + comment_insts + rating_insts + upvotes_fixed,
                          key=lambda _: _.date_created if isinstance(_, (Upvote, Rating, Comment)) else _.creation_date,
                          reverse=True)
    r = []
    if sorted_insts:
        for x in sorted_insts:
            if isinstance(x, Comment):
                s = 'comment'
            elif isinstance(x, Rating):
                s = 'rating'
            elif isinstance(x, Script):
                s = 'script'
            else:
                s = 'upvote'
            r.append((s, x))

    rendered = render_template_string(TEMPLATE, activities=r, current_month=month, today=datetime.now())
    rendered = '' if all([c == ' ' or c == '\t' or c == '\n' for c in rendered]) else rendered
    return jsonify(html=rendered)


@softwares.route('/softwares/register', methods=['GET', 'POST'])
@login_required
def register():
    """register a new software"""
    form = SoftwareForm()
    if form.validate_on_submit():
        form.save(request.form.getlist('selected_tags'))

        #update achivements
        c = db.session.query(Software.name).filter(Software.owner_id == current_user.id).count()
        goal = SoftwareAchievement.unlocked_level(c)
        if goal:
            flash('Achievement unlocked\n {} \n {}'.format(goal['name'], goal['description']), 'success')

        #update global score
        current_user.global_score += SCORE_SOFT
        current_user.save()

        #upload to s3
        if form.image.data:
            s3_upload(form.image, form.name.data.lower())
        else:
            s3_upload_from_server('static/img/placeholder.jpg', form.name.data.lower())

        return redirect(url_for('softwares.index'))

    last_soft = db.session.query(Software).order_by(desc(Software.insertion_date)).first()
    last_soft_name = last_soft.name if last_soft else None
    tot_soft_count = db.session.query(Software.name).count()
    return render_template('softwares/register_software.html', form=form,
                           last_soft_name=last_soft_name, tot_soft_count=tot_soft_count)


@softwares.route('/softwares/<name>/delete')
@login_required
def delete(name):
    """
    Delete software with specified name, delete also image on s3 if exists
    :param name: software name primary key
    :return: possible error string to display to end user
    """
    soft = Software.query.filter(Software.name == name).first_or_404()
    error = soft.delete()
    try:
        s3_delete(name)
    except:
        print("Error deleting file '{}'from s3".format(name))
    if error:
        flash("Error deleting sofware '{}'".format(soft.name), 'error')
    else:
        flash("Sofware {} successfully deleted".format(soft.name), 'success')
    return redirect(url_for('softwares.index'))


@softwares.route('/softwares/<name>')
def info(name):
    """
    get some infos on requested software name being the primary key
    count number of times no logged user call this endpoint. If > 3
    user us automatically redirected to authentification login default

    :param name: software name PK
    :return:
    """
    soft = Software.query.filter(Software.name == name).first_or_404()

    # view restriction
    # if not current_user.is_authenticated():
    #     v = session.get('nb_views', 0)
    #     session['nb_views'] = v + 1
    #
    #     if session['nb_views'] > 3:
    #         flash("Please register or log in to see more about softwares", "info")
    #         #redirect to softwares by default
    #         return redirect(url_for('auth.login', next=url_for('softwares.info', name=name)))

    show_comment_form = True if 'show_comment_form' in request.args else False

    return render_template('softwares/software.html',
                           software=soft,
                           show_comment_form=show_comment_form,
                           form=Form())


# COMMENTS and RATINGS
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/softwares/<name>/comment', methods=['GET', 'POST'])
@login_required
def comment(name):
    """
    add a comment or a rating on a software
    :param name: software name PK
    :return:
    """
    if request.method == 'GET':
        return redirect(url_for('softwares.index', name=name))
    content, rating = request.form.get('content'), request.form.get('rating')

    if content is None and rating is None:
        flash("Must post a comment or/and a rate", "danger")

    user_id = current_user.id if current_user.is_authenticated else GUEST_USER_ID
    if content:
        c = Comment(content)
        c.user_id = user_id
        c.software_id = name
        c.save()
    if rating:
        r = Rating(rating, user_id, name)
        r.save()
    return redirect(url_for('softwares.info', name=name))


@softwares.route('/softwares/<name>/comments')
def comments(name):
    soft = Software.query.filter(Software.name == name).first_or_404()
    return render_template('softwares/all_comments.html', software=soft, form=Form())


@softwares.route('/softwares/<name>/update_comment/<int:comment_id>', methods=['POST'])
@login_required
def update_comment(name, comment_id):
    soft = Software.query.filter(Software.name == name).first_or_404()
    c = Comment.query.filter(Comment.id == comment_id).first_or_404()

    c.content = request.form.get("comment-content-{}".format(comment_id))
    c.save()
    flash("Comment content successfully updated", "success")
    return redirect(url_for('softwares.comments', name=soft.name))


@softwares.route('/softwares/<name>/ratings')
def ratings(name):
    soft = Software.query.filter(Software.name == name).first_or_404()
    m = db.session.query(func.avg(Rating.rate).label('mean_rate')).filter(Rating.software_id == name).first()[0]
    return render_template('softwares/all_ratings.html', software=soft, mean=m)


# SENTENCES upvotes
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/softwares/<name>/upvote/<int:mapping_id>')
@login_required
def upvote(name, mapping_id):
    """
    upvite a particular software mapping id
    :param name:
    :param mapping_id:
    :return:
    """
    soft = Software.query.filter(Software.name == name).first_or_404()
    s_mapp = None
    for s in soft.sentences_mapping:
        if s.id == mapping_id:
            s_mapp = s
            break
    if s_mapp is None:
        abort(404)
    s_mapp.upvote += 1
    s_mapp.save()

    # create an upvote record
    upvote_inst = Upvote()
    upvote_inst.sentence_software_mapping_id = mapping_id if s_mapp is not None else abort(404)
    upvote_inst.user_id = current_user.id if current_user.is_authenticated else GUEST_USER_ID

    upvote_inst.save()

    flash("Vote taken into account ! ", "success")
    return redirect(url_for('softwares.info', name=name))


@softwares.route('/softwares/<name>/<int:mapping_id>/upvote-details')
def upvote_details(name, mapping_id):
    soft = Software.query.filter(Software.name == name).first_or_404()
    s_mapp = None
    for s in soft.sentences_mapping:
        if s.id == mapping_id:
            s_mapp = s
            break
    if s_mapp is None:
        abort(404)
    upvotes = Upvote.query.filter(Upvote.sentence_software_mapping_id == mapping_id).all()
    non_guest_count = 0
    for u in upvotes:
        if u.user is not None and u.user_id != GUEST_USER_ID:
            non_guest_count += 1
    # fix bug
    upvotes = [u for u in upvotes if u.user_id != GUEST_USER_ID and u.user is not None]
    return render_template("softwares/all_upvotes.html", software=soft, upvotes=upvotes, soft_mapping=s_mapp,
                           guest_count=s_mapp.upvote - non_guest_count)


# PROCONS routes
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/softwares/<name>/register_procon', methods=['GET', 'POST'])
@login_required
def register_procon(name):
    form = ProConsForm()
    print("KIND:", request.args.get('kind'))
    form.kind.data = request.args.get('kind') or 'pro'
    if form.validate_on_submit():
        # create new procon object
        procon = ProCons(request.form['kind'], request.form['title'], request.form['description'])
        procon.owner_id = current_user.id if current_user.is_authenticated else GUEST_USER_ID
        procon.software_name = name
        procon.save()
        flash('successfully saved !', 'success')
        return redirect(url_for('softwares.info', name=name))
    soft = Software.query.filter(Software.name == name).first_or_404()
    return render_template('softwares/register_procons.html', software=soft, form=form)


@softwares.route('/softwares/<name>/procons_upvote/<int:procon_id>')
@login_required
def upvote_procon(name, procon_id):
    user_id = current_user.id if current_user.is_authenticated else GUEST_USER_ID
    proconup = ProConsUpvote(procon_id, user_id)
    proconup.save()
    return redirect(url_for('softwares.info', name=name))


@softwares.route('/softwares/<name>/pros')
def pros(name):
    soft = Software.query.filter(Software.name == name).first_or_404()
    return render_template('softwares/all_pros.html', software=soft)


@softwares.route('/softwares/<name>/cons')
def cons(name):
    soft = Software.query.filter(Software.name == name).first_or_404()
    return render_template('softwares/all_cons.html', software=soft)


# software users routes
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/softwares/<name>/register_user')
@login_required
def register_user(name):
    """
    add a user to software users slot
    :param name:
    :return:
    """
    soft = Software.query.filter(Software.name == name).first_or_404()
    current_user.softwares_used.append(soft)
    current_user.save()
    return redirect(url_for('softwares.info', name=name))


@softwares.route('/softwares/<name>/remove_user')
@login_required
def remove_user(name):
    """
    remove a software user
    :param name:
    :return:
    """
    soft = Software.query.filter(Software.name == name).first_or_404()
    try:
        current_user.softwares_used.remove(soft)
        current_user.save()
    except ValueError:
        pass
    # return redirect(url_for('user.profile', username=current_user.username))
    return redirect(url_for('softwares.info', name=name))


# Update software informations and description
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/softwares/<name>/update', methods=['GET', 'POST'])
@login_required
def update(name):
    """
    only logged creator user or eventualy can edit software properties
    :param name: software PK
    :return:
    """
    soft = Software.query.filter(Software.name == name).first_or_404()

    # simple security check
    if soft.owner_id != current_user.id and not is_admin(current_user):
        return abort(401)
    form = SoftwareUpdateForm()
    if form.validate_on_submit():
        form.save(soft, request.form.getlist('selected_tags'))
        return redirect(url_for('softwares.info', name=name))
    return render_template('softwares/update_software.html', form=form, software=soft)


@softwares.route('/softwares/<name>/update_description', methods=['POST'])
@login_required
def update_description(name):
    soft = Software.query.filter(Software.name == name).first_or_404()

    if soft.owner_id != current_user.id and not is_admin(current_user):
        return abort(401)
    soft.algorithm_description = request.form['description']
    soft.save()
    flash('description updated', 'success')
    return redirect(url_for('softwares.info', name=name))


# RANKINGS
# ----------------------------------------------------------------------------------------------------------------------
@softwares.route('/rankings', methods=['GET'])  # @cache.cached(timeout=86400)
def rankings():
    softwares_inst = Software.query.all()
    overall_winner = max(softwares_inst, key=lambda _: _.compute_rate()) if softwares_inst else None
    # should be easier with group_by
    softwares_name = [s.name for s in softwares_inst]

    today = datetime.now()
    delta = request.args.get('last-days', 1)
    yesterday = today - timedelta(days=delta)

    # should be easier with groupby and average
    soft_rate_list = db.session.query(Software.name, Rating.rate).join(Rating).filter(
        Rating.date_created.between(str(yesterday), str(today))).all()
    last_day_user_rating_mean_by_software = {s: mean([rate[1] for rate in list(rates)]) for s, rates in
                                             groupby(soft_rate_list, key=lambda x: x[0])}
    if last_day_user_rating_mean_by_software:
        winning_software = max(last_day_user_rating_mean_by_software.items(), key=lambda _: _[1])[0]
    else:
        winning_software = "No winner today..."

    # winning upvote software
    upvotes = db.session.query(Upvote).filter(Upvote.date_created.between(str(yesterday), str(today))).all()
    last_day_upvotes_by_software = {n: len(list(up)) for n, up in
                                    groupby(upvotes, key=lambda _: _.sentence_software_mapping.software.name)}
    if last_day_upvotes_by_software:
        winning_software_upvotes = max(last_day_upvotes_by_software.items(), key=lambda _: _[1])[0]
    else:
        winning_software_upvotes = "No winner today..."

    # add missing software
    for name in softwares_name:
        if name not in last_day_user_rating_mean_by_software:
            last_day_user_rating_mean_by_software[name] = 0
        if name not in last_day_upvotes_by_software:
            last_day_upvotes_by_software[name] = 0

    # should be easier with Counter
    nb_softs_by_categories = {SOFT_MAP[i]: 0 for i in SOFT_MAP.keys()}
    for soft_category in nb_softs_by_categories.keys():
        for s in softwares_inst:
            t = {t.tag for t in s.tags}
            if soft_category in t:
                nb_softs_by_categories[soft_category] += 1
    if len(softwares_name) > 0:
        for k, v in nb_softs_by_categories.items():
            nb_softs_by_categories[k] = float(v) / len(softwares_name)
    else:
        for k in list(nb_softs_by_categories.keys()):
            nb_softs_by_categories[k] = 0.0

    upvotes_by_software_name = {}
    for name in softwares_name:
        r = {'UI': db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
            Sentence.category == 'UI', Software.name == name).all()[0][0] or 0,
             'PERFORMANCE':
                 db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                     Sentence.category == 'PERFORMANCE', Software.name == name).all()[0][0] or 0,
             'SUPPORT': db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                 Sentence.category == 'SUPPORT', Software.name == name).all()[0][0] or 0
             }
        upvotes_by_software_name[name] = r

    total_upvotes_by_software_name = {name: d['UI'] + d['PERFORMANCE'] + d['SUPPORT'] for name, d in
                                      upvotes_by_software_name.items()}

    upvotes_by_software_name_items = upvotes_by_software_name.items()
    best_ui_softwares = [(name, ups['UI']) for name, ups in
                         sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['UI'])][:5]
    best_performance_softwares = [(name, ups['PERFORMANCE']) for name, ups in
                                  sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['PERFORMANCE'])][:5]
    best_support_softwares = [(name, ups['SUPPORT']) for name, ups in
                              sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['SUPPORT'])][:5]

    # rate evolution
    rate_evolution = {}
    for name in softwares_name:

        rate_evolution[name] = {}
        test = db.session.query(Rating).join(Software).filter(Software.name == name).order_by(Rating.date_created).all()

        def grouper(rating):
            return rating.date_created.year, rating.date_created.month

        for ((year, month), items) in groupby(test, grouper):
            items_list = list(items)
            # rate_evolution[name].append({datetime(year=int(year), month=int(month), day=1): sum([i.rate for i in items_list]) / float(len(items_list))})
            rate_evolution[name][datetime(year=int(year), month=int(month), day=1)] = sum(
                [i.rate for i in items_list]) / float(len(items_list))

    sorted_dates = []
    for __, data in rate_evolution.items():
        sorted_dates += data.keys()
    sorted_dates = sorted(list(set(sorted_dates)))

    return render_template('softwares/rankings.html',
                           today=today,
                           last_day_stats=OrderedDict(last_day_user_rating_mean_by_software),
                           last_day_upvotes=OrderedDict(last_day_upvotes_by_software),
                           winning_software=winning_software,
                           winning_software_upvotes=winning_software_upvotes,
                           nb_softs_by_categories=OrderedDict(nb_softs_by_categories),
                           upvotes_by_software_name=OrderedDict(upvotes_by_software_name),
                           total_upvotes_by_software_name=OrderedDict(total_upvotes_by_software_name),
                           softwares=sorted(softwares_inst, key=lambda _: len(_.users), reverse=True),
                           sorted_dates=sorted_dates,
                           rate_evolution=rate_evolution,
                           best_ui_softwares=best_ui_softwares,
                           best_performance_softwares=best_performance_softwares,
                           best_support_softwares=best_support_softwares,
                           delta_rankings_ui=Software.pos_delta_upvotes(category='UI'),
                           delta_rankings_perf=Software.pos_delta_upvotes(category='PERFORMANCE'),
                           delta_rankings_support=Software.pos_delta_upvotes(category='SUPPORT'),
                           overall_winner=overall_winner)


@softwares.route('/workflow', methods=['GET'])
def workflow():
    return render_template('home/workflow.html')


@softwares.route('/leaderboard', methods=['GET'])
def leaderboard():
    users = db.session.query(User).order_by(desc(User.global_score)).all()
    return render_template('home/leaderboard.html', users=users)


@softwares.route('/about', methods=['GET'])
def about():
    return render_template('home/home_layout.html')


@softwares.route('/faq', methods=['GET'])
def faq():
    return render_template('home/FAQ.html')
