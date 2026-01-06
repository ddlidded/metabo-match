# -*- coding:utf-8 -*-
"""
news/blog views
"""
from flask import Blueprint, request, flash, redirect, url_for
from flask_wtf import FlaskForm as Form
import markdown2

from metabomatch.flaskbb.utils.helpers import render_template
from metabomatch.news.models import Article
from sqlalchemy import desc, asc

news = Blueprint('news', __name__, template_folder='../templates')

NEWS_PER_PAGE = 5


@news.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    articles = Article.query.order_by(desc(Article.creation_date)).paginate(page=page, per_page=NEWS_PER_PAGE, error_out=True)
    print([a.creation_date for a in articles.items])
    return render_template('news/news.html', articles=articles, form=Form())


@news.route('/add_post', methods=['POST'])
def add_post():
    content = request.form.get('content')
    title = request.form.get('title')
    if not content or not title:
        flash('Must have a content and a title...', 'warning')
    a = Article(title, content)
    a.save()

    return redirect(url_for('news.index'))
