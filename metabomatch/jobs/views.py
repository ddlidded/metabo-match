import os

try:
    from metabomatch.private_keys import GUEST_USER_ID
except ImportError:
    GUEST_USER_ID = os.environ.get('GUEST_USER_ID')
from sqlalchemy import func, desc
import markdown2

from flask import Blueprint, request, redirect, url_for, flash
from flask_login import login_required, current_user

from metabomatch.extensions import db

from metabomatch.flaskbb.utils.helpers import render_template
from metabomatch.jobs.forms import JobForm
from metabomatch.jobs.models import Job, JobTags
from metabomatch.achievements import JobAchievement, SCORE_JOB

jobs = Blueprint("jobs", __name__, template_folder="../../templates")


JOBS_PER_PAGE = 20


@jobs.route('/')
def index():
    page = request.args.get("page", 1, type=int)
    tag = request.args.get('tag')
    if tag is not None:
        jobs_obj = Job.query.join(Job.job_tags).filter(JobTags.name == tag)\
            .order_by(desc(Job.creation_date)).paginate(page=page, per_page=JOBS_PER_PAGE, error_out=True)
    else:
        jobs_obj = Job.query.paginate(page=page, per_page=JOBS_PER_PAGE, error_out=True)
    return render_template('jobs/jobs.html', jobs=jobs_obj)


@jobs.route('/register', methods=['GET', 'POST'])  # @login_required
def register():
    form = JobForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            form.save()
            goal = JobAchievement.unlocked_level(len(current_user.posted_jobs))
            if goal:
                flash("Achievement unlock: {}, {}, level {}".format(JobAchievement.name, goal['name'], goal['level']),
                      'success')
            current_user.global_score += SCORE_JOB
            current_user.save()
        else:
            form.save(user_id=GUEST_USER_ID)
        return redirect(url_for('jobs.index'))

    #---perform some queries to get some statistics
    jobs_count = Job.query.count()
    top_companies = db.session.query(func.count(Job.company), Job.company)\
        .group_by(Job.company).order_by(func.count(Job.company)).limit(5)
    sum_views = db.session.query(func.sum(Job.nb_viewed))[0][0]
    return render_template('jobs/register_job.html', form=form,
                           jobs_count=jobs_count, sum_views=sum_views, top_companies=top_companies)


@jobs.route('/<int:job_id>')
@jobs.route('/<int:job_id>-<slug>')
def info(job_id, slug=None):
    job = Job.query.filter(Job.id == job_id).first_or_404()
    job.nb_viewed += 1
    job.save()

    # convert markdown to html
    job_description, job_motivation = markdown2.markdown(job.description), markdown2.markdown(job.motivation)
    return render_template('jobs/job.html', job=job, html_description=job_description, html_motivation=job_motivation)


@jobs.route('/close/<int:job_id>')
@login_required
def close(job_id):
    job = Job.query.get(job_id)
    job.is_closed = True
    job.save()
    flash('Job offer closed.', 'success')
    return redirect(url_for('jobs.index'))
