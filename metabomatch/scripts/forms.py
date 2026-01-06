"""
scripts forms
"""
import requests
from flask_wtf import FlaskForm as Form
from flask_login import current_user

from wtforms import StringField, SelectField, TextAreaField
from wtforms.validators import DataRequired, URL, Optional

from metabomatch.scripts.models import Script, ScriptTags
from metabomatch.extensions import db
from metabomatch.softwares.models import Software


class ScriptForm(Form):
    """
    Script form
    """
    pg = ['R', 'Python', 'C', 'C++', 'Javascript', 'Java', 'Markdown']

    software = SelectField("software", description="Choose a software if your script is related to a software")
    title = StringField("title*", validators=[DataRequired(message="title is required")])
    programming_language = SelectField("programming language", choices=[(p, p) for p in pg])
    tags = StringField("tags", default="")

    github_gist_url = StringField('github gist url', validators=[Optional(), URL(message="Not a valid url")])

    description = TextAreaField("description", default='NA', validators=[Optional()])
    content = TextAreaField("content*", validators=[Optional()])

    def save(self, software_name, user_id=None):
        script = Script(self.title.data, self.programming_language.data)
        script.description = self.description.data
        script.user_id = user_id or current_user.id
        if software_name != 'None' and software_name != '---':
            script.software_id = software_name
        else:
            script.software_id = None
        script.up_votes = 0

        if self.github_gist_url.data:
            script.github_gist_url = self.github_gist_url.data
            script.content = requests.get(self.github_gist_url.data + '/raw').text
        else:
            script.content = self.content.data

        #tags
        tags = self.tags.data.split(",")
        l = []
        for tag in tags:
            t = db.session.query(ScriptTags).get(tag)
            if t is None:
                new_tag = ScriptTags(tag).save()
                l.append(new_tag)
            else:
                l.append(t)
        script.script_tags = l

        return script.save()

    def get_softwares(self):
        self.software.choices = [('---', 'None')] + [(s[0], s[0]) for s in db.session.query(Software.name).all()]

    def validate(self, extra_validators=None):
        """
        :returncustom validation logic
        """
        is_valid = super().validate(extra_validators=extra_validators)
        if not self.github_gist_url.data and not self.content.data:
            self.content.errors.append("If no gist url is provided, content must be filled")
            return False
        elif self.github_gist_url.data and self.content.data:
            self.content.errors.append("Both github gist url and content are defined, fill only one")
            return False
        else:
            return is_valid

