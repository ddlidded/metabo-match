from datetime import datetime

from flask_wtf import FlaskForm as Form
from flask_login import current_user
from metabomatch.extensions import db
from metabomatch.jobs.models import Job, JobTags

from wtforms import StringField, TextAreaField, DateField
from wtforms.validators import DataRequired, URL, Optional, Email


class JobForm(Form):
    company = StringField('company*', validators=[DataRequired(message='missing company name')])

    #fixed ace was empty if validator fails that lead to a TODO
    company_url = StringField('company link', validators=[Optional()])  # , URL(message='not a valid url')])
    workplace = StringField('workplace*', validators=[DataRequired(message='workplace is missing')])

    name = StringField('name*', validators=[DataRequired(message='missing job name')])

    description = TextAreaField('description*',
                                validators=[DataRequired(message='missing job description')],
                                description='Use markdown to write your job offer')

    motivation = TextAreaField('motivation', validators=[Optional()],
                               description='Describe in one sentence why programmers should join your company')

    apply_date_limit = DateField('apply limit date', format='%d-%m-%Y', validators=[Optional()])
    contact_email = StringField('contact_email*',
                                validators=[DataRequired(message="missing contact email"),
                                            Email(message="not a valid email")])

    job_tags = StringField('tags', description='programming languages, expertise...', default='')

    def save(self, user_id=None):

        job = Job(self.company.data, self.company_url.data)
        job.name = self.name.data

        job.workplace = self.workplace.data

        job.description = self.description.data
        job.motivation = self.motivation.data
        job.apply_date_limit = self.apply_date_limit.data
        job.contact_email = self.contact_email.data

        job.user_id = current_user.id or user_id
        job.is_closed = False
        #tags
        tags = self.job_tags.data.split(",")
        l = []
        for tag in tags:
            t = db.session.query(JobTags).get(tag)
            if t is None:
                new_tag = JobTags(tag).save()
                l.append(new_tag)
            else:
                l.append(t)
        job.job_tags = l

        #return instance object
        return job.save()
