# -*- coding: utf-8 -*-
"""
metabomatch: softwares model
"""
from datetime import datetime
import json

from Bio import Entrez

from metabomatch.extensions import db, cache, github
from metabomatch.flaskbb.forum.models import Category
from sqlalchemy import func
from textblob import TextBlob

from metabomatch.flaskbb.utils.serialization import SerializableMixin

Entrez.email = 'cram@hotmail.fr'

# tags softwares mapping
tags_software_mapping = db.Table(
    'tags_software_mapping',
    db.Column('software_name',
              db.String(),
              db.ForeignKey('softwares.name'),
              nullable=False),
    db.Column('tag_name',
              db.String(),
              db.ForeignKey('tags.tag'),
              nullable=False)
)

# users-softwares
user_softwares_mapping = db.Table(
    'users_software_mapping',
    db.Column('user_id',
              db.Integer(),
              db.ForeignKey('users.id'),
              nullable=False),
    db.Column('software_name',
              db.String(),
              db.ForeignKey('softwares.name'),
              nullable=False)
)


class Sentence(db.Model):
    """Description sentence"""

    __tablename__ = 'sentences'

    categories = {'UI', 'PERFORMANCE', 'SUPPORT'}

    id = db.Column(db.Integer, primary_key=True)
    sentence = db.Column(db.String)
    category = db.Column(db.String)

    def __init__(self, sentence, category):
        self.sentence = sentence

        if category not in Sentence.categories:
            raise ValueError("Sentence wrong category")

        self.category = category


class SentenceSoftwareMapping(db.Model):
    """
    mapping between softwares and sentences describing it
    """

    __tablename__ = 'sentences_software_mapping'

    id = db.Column(db.Integer, primary_key=True)
    software_id = db.Column(db.String, db.ForeignKey('softwares.name'), nullable=False)
    sentence_id = db.Column(db.Integer, db.ForeignKey('sentences.id'), nullable=False)
    upvote = db.Column(db.Integer, default=0)  # more precisely upvote counts

    # fixed deleted manually, find how to do that automatically
    software = db.relationship('Software', backref='sentences_mapping')
    sentence = db.relationship('Sentence', backref='sentences_mapping')

    def __init__(self, software_id, sentence_id):
        self.software_id = software_id
        self.sentence_id = sentence_id

    def save(self):
        db.session.add(self)
        db.session.commit()


class Upvote(SerializableMixin, db.Model):
    __tablename__ = 'upvotes'

    id = db.Column(db.Integer, primary_key=True)
    sentence_software_mapping_id = db.Column(db.Integer, db.ForeignKey("sentences_software_mapping.id"), nullable=False)
    date_created = db.Column(db.Date, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # case user was not identified

    sentence_software_mapping = db.relationship('SentenceSoftwareMapping',
                                                foreign_keys=[sentence_software_mapping_id],
                                                backref='upvotes')
    user = db.relationship('User', foreign_keys=[user_id], backref='upvotes', lazy='joined')

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class ProCons(db.Model):
    __tablename__ = 'procons'
    possible_kinds = {'pro', 'con'}

    id = db.Column(db.Integer, primary_key=True)

    kind = db.Column(db.String, nullable=False, default='pro')
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    # upvote = db.Column(db.Integer, default=0)  # more precisely upvote counts

    # Foreign keys
    software_name = db.Column(db.String, db.ForeignKey("softwares.name"), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Relationship
    software = db.relationship('Software', foreign_keys=[software_name], backref='procons')
    owner = db.relationship('User', foreign_keys=[owner_id], backref='procons')

    def __init__(self, kind, title, description):
        if kind not in ProCons.possible_kinds:
            kind = 'pro'
        self.kind = kind
        self.title = title
        self.description = description

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.remove(self)
        db.session.commit()


class ProConsUpvote(db.Model):
    __tablename__ = 'procons_upvotes'

    id = db.Column(db.Integer, primary_key=True)

    upvote_date = db.Column(db.DateTime, default=datetime.utcnow())

    procons_id = db.Column(db.Integer, db.ForeignKey("procons.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # case user was not identified

    # RelationShip
    procons = db.relationship('ProCons', foreign_keys=[procons_id], backref='procons_upvotes')
    user = db.relationship('User', foreign_keys=[user_id], backref='procons_upvotes', lazy='joined')

    def __init__(self, procons_id, user_id):
        self.procons_id = procons_id
        self.user_id = user_id

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.remove(self)
        db.session.commit()


class Tag(db.Model):
    """Tag model representing step in the classical metabolomic pipeline"""

    __tablename__ = "tags"

    tag = db.Column(db.String(200), primary_key=True)

    def __init__(self, tag):
        self.tag = tag


class Rating(SerializableMixin, db.Model):
    """Represents the rate a user can add to a software"""

    __tablename__ = 'ratings'

    id = db.Column(db.Integer, primary_key=True)
    rate = db.Column(db.Integer, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    software_id = db.Column(db.String, db.ForeignKey("softwares.name"), nullable=False)

    #fixed defined in user model
    #user = db.relationship('User', foreign_keys=[user_id])
    #software = db.relationship('Software', foreign_keys=[software_id])

    def __init__(self, rate, user_id, software_id):
        self.rate = rate
        self.user_id = user_id
        self.software_id = software_id

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self


class Comment(SerializableMixin, db.Model):
    """Comment by user on software"""

    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    software_id = db.Column(db.String, db.ForeignKey("softwares.name"), nullable=False)

    #fixed --- defined in user model
    # user = db.relationship('User', foreign_keys=[user_id])
    #software = db.relationship('Software', foreign_keys=[software_id])

    def __init__(self, content):
        self.content = content

    def save(self):
        """todo: add a count of comments"""
        db.session.add(self)
        db.session.commit()
        return self

    def sentiment_analysis(self):
        """
        :return sentiment object containing polarity and subjectivity field
        """
        return TextBlob(self.content).sentiment

    def get_content(self):
        return self.content.replace('\n', '<br/>')


class Software(db.Model):
    """
    Software models
    ===============

    removed column: `nb_users` unecessary duplicated information (relationship with users instread)

    """
    __tablename__ = "softwares"

    name = db.Column(db.String(200), primary_key=True)
    insertion_date = db.Column(db.DateTime, default=datetime.utcnow())
    organization = db.Column(db.String(200))  # institute or company which created the software
    programming_language = db.Column(db.String(200))
    website = db.Column(db.String(500))

    #todo what to do with these ?
    algorithm_description = db.Column(db.Text())
    algorithm_originality = db.Column(db.Integer())
    additional_info = db.Column(db.Text())

    github_link = db.Column(db.String(200))
    is_maintained = db.Column(db.Boolean())
    current_version = db.Column(db.String(200))

    publication_link = db.Column(db.String(200))
    omictools_id = db.Column(db.String(200))

    download_link = db.Column(db.String(200))

    #  for comparisons
    nb_citations = db.Column(db.Integer(), default=0)  # Entrez biopython module
    nb_downloads = db.Column(db.Integer(), default=0)  # on Github
    nb_commits_month = db.Column(db.Integer(), default=0)
    nb_commits_year = db.Column(db.Integer(), default=0)
    nb_maintainers = db.Column(db.Integer(), default=0)
    nb_issues = db.Column(db.Integer(), default=0)
    nb_opened_issues = db.Column(db.Integer(), default=0)

    nb_winner_of_the_day_rate = db.Column(db.Integer, default=0)
    nb_winner_of_the_day_upvote = db.Column(db.Integer, default=0)

    # position in softwares
    last_position_by_global_rate = db.Column(db.Integer, default=0)
    last_position_by_tot_upvotes = db.Column(db.Integer, default=0)
    last_position_by_ui_upvotes = db.Column(db.Integer, default=0)
    last_position_by_perf_upvotes = db.Column(db.Integer, default=0)
    last_position_by_support_upvotes = db.Column(db.Integer, default=0)
    last_position_by_users_rates = db.Column(db.Integer, default=0)

    #fixed will be a function call inside template
    #mean_user_rate

    #fixed---this is a duplicate list users
    #nb_users = db.Column(db.Integer())

    #fixed will be a function call inside template
    # global_rate = db.Column(db.Float(), default=0.0)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # relationships
    owner = db.relationship('User', uselist=False, backref='software_owner', foreign_keys=[owner_id])
    comments = db.relationship('Comment', order_by='Comment.date_created', backref='software', cascade='all, delete-orphan')
    ratings = db.relationship('Rating', order_by='Rating.date_created', backref='software', cascade='all, delete-orphan')
    tags = db.relationship('Tag', secondary=tags_software_mapping, backref='softwares', lazy='joined')
    users = db.relationship('User', secondary=user_softwares_mapping, backref='softwares_used')

    scripts = db.relationship('Script', backref='software')

    def __init__(self, name, organization="", pg_language=""):
        self.name = name
        self.organization = organization
        self.programming_language = pg_language

    def __repr__(self):
        return "<{} {}>".format(self.__class__.__name__, self.name)

    def _format_tags(self):
        return [str(tag.tag) for tag in self.tags]

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self

    def delete(self):
        mappings = SentenceSoftwareMapping.query.filter(SentenceSoftwareMapping.software_id == self.name).all()
        error = ""
        try:
            for m in mappings:
                db.session.delete(m)
            db.session.commit()

            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            error = "Error occured when trying to delete software: " + e.message
            db.session.rollback()
        return error

    def remove_user(self, user):
        self.users.remove(user)
        return self.save()

    def get_category_url(self):
        cat = Category.query.filter(Category.title == self.name).first()
        if cat is None:
            pass
        return cat.url

    def github_owner_repo(self):
        #could be a property
        if self.github_link is None or not self.github_link:
            return None, None
        return self.github_link.split('/')[-2:]

    def get_publication_id(self):
        if self.publication_link is not None:
            return self.publication_link.split('/')[-1]
        return None

    def mean_rate(self):
        if not self.ratings:
            return 'NA'
        return sum([r.rate for r in self.ratings]) / float(len(self.ratings))

    def compute_rate(self):
        max_val = 0
        if self.publication_link is not None:
            max_val += 15.0
        if self.is_maintained:
            max_val += 15.0
        if self.github_link is not None:
            max_val += 10.0
        if self.download_link is not None:
            max_val += 10.0

        #malus
        if self.github_link is not None:
            issues, opened_issues = self.nb_issues, self.nb_opened_issues
            year_commits, month_commits = self.nb_commits_year, self.nb_commits_month

            max_val -= (issues * 0.1 + opened_issues * 0.2)
            if year_commits <= 20:
                max_val -= min(6, year_commits * 0.5)
            else:
                max_val += 6

            #bonus
            max_val += min(4, self.nb_maintainers * 0.75)

        max_val += min(20, self.nb_citations * 0.75)
        upvotes_count = db.session.query(Upvote.id).join(SentenceSoftwareMapping).filter(
            SentenceSoftwareMapping.software_id == self.name).count()
        max_val += min(30, upvotes_count * 0.25)
        return round(max_val)

    def populate(self):
        #todo parallel processing of get requests
        # from multiprocessing import Pool
        # p = Pool(processes=4)
        # github_infos = self.github_owner_repo()
        # func_args = ((get_publication_citation_nb, (self.get_publication_id(),)),
        #              (get_nb_maintainers, github_infos),
        #              (get_nb_commits, github_infos),
        #              (get_nb_issues, github_infos),
        #              (get_nb_downloads, github_infos))
        #
        # for func, args in func_args:
        #     p.apply(func, *args)

        self.nb_citations = get_publication_citation_nb(self.get_publication_id())
        github_infos = self.github_owner_repo()
        self.nb_maintainers = get_nb_maintainers(*github_infos)
        self.nb_commits_year, self.nb_commits_month = get_nb_commits(*github_infos)
        self.nb_issues, self.nb_opened_issues = get_nb_issues(*github_infos)
        self.nb_downloads = get_nb_downloads(*github_infos)

    @property
    def pros(self):
        # todo: replace pro by constant
        return sorted([p for p in self.procons if p.kind == 'pro'], key=lambda x: -len(x.procons_upvotes))

    @property
    def cons(self):
        return sorted([p for p in self.procons if p.kind == 'con'], key=lambda x: -len(x.procons_upvotes))

    @staticmethod
    def set_rankings(softwares=None):
        if softwares is None:
            softwares = Software.query.all()

        softwares.sort(key=lambda _: _.compute_rate(), reverse=True)

        for i in range(len(softwares)):
            softwares[i].last_position_by_global_rate = i + 1
            softwares[i].save()

        softwares_tot, softwares_ui, softwares_perf, softwares_support = [], [], [], []
        for s in softwares:
            c_tot = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software) \
                .filter(Software.name == s.name).all()[0][0]
            softwares_tot.append((s, c_tot))

            c_ui = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                Sentence.category == 'UI', Software.name == s.name).all()[0][0]
            softwares_ui.append((s, c_ui))

            c_perf = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                Sentence.category == 'PERFORMANCE', Software.name == s.name).all()[0][0]
            softwares_perf.append((s, c_perf))

            c_support = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                Sentence.category == 'SUPPORT', Software.name == s.name).all()[0][0]
            softwares_support.append((s, c_support))

        softwares_tot.sort(key=lambda x: x[1], reverse=True)
        for i in range(len(softwares_tot)):
            softwares_tot[i][0].last_position_by_tot_upvotes = i + 1
            softwares_tot[i][0].save()

        softwares_ui.sort(key=lambda x: x[1], reverse=True)
        for i in range(len(softwares_ui)):
            softwares_ui[i][0].last_position_by_ui_upvotes = i + 1
            softwares_ui[i][0].save()

        softwares_perf.sort(key=lambda x: x[1], reverse=True)
        for i in range(len(softwares_perf)):
            softwares_perf[i][0].last_position_by_perf_upvotes = i + 1
            softwares_perf[i][0].save()

        softwares_support.sort(key=lambda x: x[1], reverse=True)
        for i in range(len(softwares_support)):
            softwares_support[i][0].last_position_by_support_upvotes = i + 1
            softwares_support[i][0].save()

        softwares.sort(key=lambda _: _.mean_rate(), reverse=True)
        for i in range(len(softwares)):
            softwares[i].last_position_by_users_rate = i + 1
            softwares[i].save()

    @staticmethod
    def pos_delta_by_global_rate():
        softwares = Software.query.all()
        softwares.sort(key=lambda _: _.compute_rate(), reverse=True)
        actual = {softwares[i].name: i + 1 for i in range(len(softwares))}
        return {s.name: s.last_position_by_global_rate - actual[s.name] for s in softwares}

    @staticmethod
    def pos_delta_upvotes(category=None):

        softwares = Software.query.all()
        softwares_perf = []
        for software in softwares:
            if category is None:
                c = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                    Software.name == software.name).all()[0][0]
            else:
                c = db.session.query(func.sum(SentenceSoftwareMapping.upvote)).join(Sentence).join(Software).filter(
                    Sentence.category == category, Software.name == software.name).all()[0][0]
            softwares_perf.append((software, c))

        softwares_perf.sort(key=lambda _: _[1], reverse=True)
        actual = {softwares_perf[i][0].name: i + 1 for i in range(len(softwares_perf))}
        if category == 'UI':
            return {s[0].name: s[0].last_position_by_ui_upvotes - actual[s[0].name] for s in softwares_perf}
        elif category == 'PERFORMANCE':
            return {s[0].name: s[0].last_position_by_perf_upvotes - actual[s[0].name] for s in softwares_perf}
        elif category == 'SUPPORT':
            return {s[0].name: s[0].last_position_by_support_upvotes - actual[s[0].name] for s in softwares_perf}
        else:
            pass


###---multiprocessing for requesting github API
def get_publication_citation_nb(publication_id):
    h = Entrez.elink(dbfrom="pubmed", db="pmc", LinkName="pubmed_pmc_refs", from_uid=publication_id)
    result = Entrez.read(h)
    nb_citations = 0
    try:
        nb_citations = len([link["Id"] for link in result[0]["LinkSetDb"][0]["Link"]])
    except IndexError:
        pass
    return nb_citations


# GITHUB BACKEND
def get_nb_maintainers(owner, repo):
    if owner is None:
        return 0

    rep = github.get("".join(['repos/', owner, '/', repo, '/contributors']))
    return len(rep)


def get_nb_commits(owner, repo):
    if owner is None:
        return 0, 0
    rep = github.get("".join(['repos/', owner, '/', repo, '/stats/commit_activity']))
    print(rep)
    if not rep:
        return 0, 0

    year_activity = sum([r['total'] for r in rep])
    # get only last four weeks
    last_month_activity = sum([r['total'] for r in rep[-4:]])
    return year_activity, last_month_activity


def get_nb_issues(owner, repo):
    """GET /repos/:owner/:repo/issues"""
    if owner is None:
        return 0, 0
    rep = github.get("".join(['repos/', owner, '/', repo, '/issues']))
    opened = 0
    for r in rep:
        if r['state'] == 'open':
            opened += 1
    return len(rep), opened


def get_nb_downloads(owner, repo):
    if owner is None:
        return 0
    rep = github.get("".join(['repos/', owner, '/', repo, '/releases']))

    c = 0
    for r in rep:
        c += r.get('downloads_count', 0)
    return c










