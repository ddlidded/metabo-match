# -*- coding: utf-8 -*-
"""
scripts views
-------------
"""
import os
from flask_wtf import FlaskForm as Form
from metabomatch.achievements import ScriptAchievement, SCORE_SCRIPT

try:
    from metabomatch.private_keys import GUEST_USER_ID
except ImportError:
    GUEST_USER_ID = os.environ.get('GUEST_USER_ID')

from sqlalchemy import desc, and_
from flask import Blueprint, request, redirect, url_for, flash

from flask_login import login_required, current_user

from metabomatch.flaskbb.utils.helpers import render_template
from metabomatch.scripts.models import Script, ScriptTags
from metabomatch.softwares.models import Software
from metabomatch.scripts.forms import ScriptForm


scripts = Blueprint('scripts', __name__, template_folder="../templates")

SCRIPTS_PER_PAGE = 5


@scripts.route('/')
def index():
    page = request.args.get("page", 1, type=int)
    software, tags = request.args.get('software'), request.args.get('tags')
    softwares = [s.name for s in Software.query.distinct(Software.name)]

    not_tags = tags is None or not tags
    tags = tags is not None and tags

    if software is not None and not_tags:
        if software == '---':
            filtered_scripts = Script.query.filter(Script.software_id == None).order_by(desc(Script.creation_date))\
                .paginate(page=page, per_page=SCRIPTS_PER_PAGE, error_out=True)
        else:
            filtered_scripts = Script.query.join(Software).filter(Software.name == software)\
                .paginate(page=page, per_page=SCRIPTS_PER_PAGE, error_out=True)
    elif (software is None or software == '---') and tags:
        tags_list = tags.split(',')
        filtered_scripts = Script.query.join(Script.script_tags).filter(ScriptTags.name.in_(tags_list))\
            .paginate(page=page, per_page=SCRIPTS_PER_PAGE, error_out=True)
    elif software is not None and tags:
        tags_list = tags.split(',')
        filtered_scripts = Script.query.join(Software).join(Script.script_tags)\
                                                      .filter(and_(Software.name == software, ScriptTags.name.in_(tags_list)))\
            .paginate(page=page, per_page=SCRIPTS_PER_PAGE, error_out=True)
    else:
        filtered_scripts = Script.query.order_by(desc(Script.creation_date)).paginate(page=page, per_page=SCRIPTS_PER_PAGE, error_out=True)
    return render_template('scripts/scripts.html',
                           scripts=filtered_scripts,
                           softwares=softwares,
                           search_form=Form())


@scripts.route('/register', methods=['GET', 'POST'])  # @login_required
def register():
    form = ScriptForm()
    form.get_softwares()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            form.save(request.form['software'])
            goal = ScriptAchievement.unlocked_level(len(current_user.scripts))
            if goal:
                flash("Achievement unlock: {}, {}, level {}".format(ScriptAchievement.name, goal['name'],
                                                                    goal['level']), 'success')
            # update score
            current_user.global_score += SCORE_SCRIPT
            current_user.save()
        else:
            form.save(request.form['software'], GUEST_USER_ID)
        return redirect(url_for('scripts.index'))

    # return template for get request
    return render_template('scripts/register_script.html', form=form)


@scripts.route('/<int:script_id>')
@scripts.route('/<int:script_id>-<slug>')
def info(script_id, slug=None):
    sc = Script.query.filter(Script.id == script_id).first_or_404()
    form = ScriptForm()
    form.get_softwares()
    return render_template('scripts/script.html', script=sc, form=Form(), form_software=form)


@scripts.route('/<int:script_id>/upvote')
def upvote(script_id):
    sc = Script.query.filter(Script.id == script_id).first_or_404()
    sc.up_voted()
    sc.save()
    return redirect(url_for('scripts.info', script_id=script_id, slug=sc.slug))


@scripts.route('/<int:script_id>/update_content', methods=['POST'])
@login_required
def update_content(script_id):
    sc = Script.query.filter(Script.id == script_id).first_or_404()
    sc.content = request.form['content']
    sc.save()
    return redirect(url_for('scripts.index'))


@scripts.route('/<int:script_id>/update_software', methods=['POST'])
@login_required
def update_software(script_id):
    sc = Script.query.filter(Script.id == script_id).first_or_404()
    software_name = request.form['software']
    if software_name == '---':
        sc.software_id = None
    else:
        sc.software_id = software_name
    sc.save()
    flash('successfully updated script software', 'success')
    return redirect(url_for('scripts.info', script_id=script_id, slug=sc.slug))
