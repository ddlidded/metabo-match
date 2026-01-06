"""
Softwares forms
"""
from flask_login import current_user
from flask_wtf import FlaskForm as Form, RecaptchaField
from wtforms import StringField, IntegerField, BooleanField, SelectField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, regexp, ValidationError, Optional, URL

from metabomatch.flaskbb.forum.models import Category, Forum
from metabomatch.flaskbb.utils.populate import create_sentences_mapping

from metabomatch.extensions import db
from metabomatch.softwares.models import Software, Tag, Sentence, ProCons


class SoftwareForm(Form):
    """Software form"""

    name = StringField("name*", validators=[DataRequired(message="You must provide a software name")])
    organization = StringField("organization")
    pg_language = StringField("programming language")

    image = FileField('image', validators=[Optional()])

    website = StringField("website", validators=[Optional(), URL()])
    github_url = StringField('github_url', validators=[Optional(), URL(message="Not a valid url")])

    is_maintained = BooleanField("is maintained ?")
    current_version = StringField("current version")

    publication_link = StringField("publication link", validators=[Optional(), URL(message="Not a valid url")])
    omictools_id = StringField("omictools id")

    download_link = StringField("download link", validators=[Optional(), URL(message="Not a valid url")])

    def validate(self, extra_validators=None):
        is_valid = super().validate(extra_validators=extra_validators)
        softs = Software.query.filter(Software.name.ilike('%' + self.name.data + '%')).all()
        if not softs:
            return is_valid
        self.name.errors.append("A software with that name already exists...")
        return False

    def save(self, selected_tags):
        soft = Software(self.name.data, self.organization.data, self.pg_language.data)
        soft.owner_id = current_user.id

        soft.website = self.website.data
        soft.github_link = self.github_url.data
        soft.is_maintained = self.is_maintained.data

        soft.current_version = self.current_version.data

        soft.publication_link = self.publication_link.data
        soft.download_link = self.download_link.data

        #---associate tags
        soft.tags = [db.session.query(Tag).filter(Tag.tag == t).first() for t in selected_tags]

        #---create sentence mapping
        soft.sentences_mapping = create_sentences_mapping(Sentence.query.all(), soft.name)

        print("CURRENT USER ID:", current_user.id)

        soft.save()

        #---create a new category and associated forum
        category_title = soft.name
        category = Category(title=category_title, description="{} category".format(soft.name))
        category.save()

        for f in (('Installation', 'Installation problems and troubleshooting, versions'),
                  ('Algorithm', 'Questions about alogrithm used'),
                  ('Parameters options', 'Common parameters for some common experiments'),
                  ('Requests', 'Message to developpers ?')):
            forum_title = "{}".format(f[0])
            forum = Forum(title=forum_title, description=f[1],
                          category_id=category.id)
            forum.save()

        #---finally return newly created software
        return soft


class SoftwareUpdateForm(SoftwareForm):

    def __init__(self):
        super().__init__()

    def validate(self, extra_validators=None):
        return super().validate(extra_validators=extra_validators)

    def save(self, soft, selected_tags):
        """
        :param soft: passed from the view function ensuring that name exists in the database
        :param selected_tags:
        :return:
        """
        soft.organization = self.organization.data
        soft.website = self.website.data
        soft.github_link = self.github_url.data
        soft.is_maintained = self.is_maintained.data

        soft.current_version = self.current_version.data

        soft.publication_link = self.publication_link.data
        soft.download_link = self.download_link.data

        #---associate tags
        soft.tags = [db.session.query(Tag).filter(Tag.tag == t).first() for t in selected_tags]

        return soft.save()


class ProConsForm(Form):
    kind = SelectField("Pro or Con ?", description="Select the appropriate tag",
                       choices=[(p, p) for p in {'pro', 'con'}])
    title = StringField('title', validators=[DataRequired(message='a title is needed')])
    description = TextAreaField('short description', validators=[Optional()])
