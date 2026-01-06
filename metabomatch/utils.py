from collections import OrderedDict
import random
import itertools
try:
    import boto
except Exception:
    boto = None
from metabomatch.extensions import db
from metabomatch.softwares.models import Software, SentenceSoftwareMapping, Sentence
import os
from sqlalchemy import func

try:
    from metabomatch.private_keys import S3_KEY, S3_BUCKET, S3_SECRET, S3_UPLOAD_DIRECTORY
except ImportError:
    S3_UPLOAD_DIRECTORY, S3_SECRET, S3_BUCKET, S3_KEY = '', '', '', ''

from werkzeug.utils import secure_filename


def s3_upload(source_file, destination_filename, acl='public-read'):
    """ Uploads WTForm File Object to Amazon S3

        Expects following app.config attributes to be set:
            S3_KEY              :   S3 API Key
            S3_SECRET           :   S3 Secret Key
            S3_BUCKET           :   What bucket to upload to
            S3_UPLOAD_DIRECTORY :   Which S3 Directory.

        The default sets the access rights on the uploaded file to
        public-read.  It also generates a unique filename via
        the uuid4 function combined with the file extension from
        the source file.
    """
    if boto is None:
        raise RuntimeError("boto is required for S3 uploads")

    source_filename = secure_filename(source_file.data.filename)
    source_extension = os.path.splitext(source_filename)[1]

    # Connect to S3 and upload file.
    conn = boto.connect_s3(os.environ.get('S3_KEY') or S3_KEY, os.environ.get("S3_SECRET") or S3_SECRET)
    b = conn.get_bucket(os.environ.get("S3_BUCKET") or S3_BUCKET)

    sml = b.new_key("/".join([os.environ.get("S3_UPLOAD_DIRECTORY") or S3_UPLOAD_DIRECTORY, destination_filename]))
    sml.set_contents_from_string(source_file.data.read())
    sml.set_acl(acl)

    return destination_filename


def s3_upload_from_server(source_file, destination_filename, acl='public-read'):
    """
    Directly upload a file existing on the server
    :param source_file:
    :param destination_filename:
    :param acl:
    :return:
    """
    if boto is None:
        raise RuntimeError("boto is required for S3 uploads")
    conn = boto.connect_s3(os.environ.get('S3_KEY') or S3_KEY, os.environ.get("S3_SECRET") or S3_SECRET)
    b = conn.get_bucket(os.environ.get("S3_BUCKET") or S3_BUCKET)

    sml = b.new_key("/".join([os.environ.get("S3_UPLOAD_DIRECTORY") or S3_UPLOAD_DIRECTORY, destination_filename]))
    sml.set_contents_from_filename(source_file)
    sml.set_acl(acl)


def s3_delete(key):
    """
    delete a key from config bucket
    :param key: here it will be a software name for example
    :return:
    """
    if boto is None:
        raise RuntimeError("boto is required for S3 deletes")
    conn = boto.connect_s3(os.environ.get('S3_KEY') or S3_KEY, os.environ.get("S3_SECRET") or S3_SECRET)
    b = conn.get_bucket(os.environ.get("S3_BUCKET") or S3_BUCKET)
    return b.delete_key(key)


def mean(l):
    return float(sum(l)) / len(l)


def best_softs_by_cat():
    softwares_name = db.session.query(Software.name).all()
    softwares_name = (s[0] for s in softwares_name)
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

    upvotes_by_software_name_items = upvotes_by_software_name.items()
    if not upvotes_by_software_name_items:
        return OrderedDict()
    best_ui_software = 'UI', sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['UI'])[0][0]
    best_performance_software = 'PERFORMANCE', \
                                sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['PERFORMANCE'])[0][0]
    best_support_software = 'SUPPORT', sorted(upvotes_by_software_name_items, key=lambda _: -_[1]['SUPPORT'])[0][0]
    results = OrderedDict((best_ui_software, best_performance_software, best_support_software))
    print(results)
    return OrderedDict((best_ui_software, best_performance_software, best_support_software))


def sample_wr(population, k):
    """Chooses k random elements (with replacement) from a population"""

    n = len(population)
    _random, _int = random.random, int  # speed hack
    return [population[_int(_random() * n)] for _ in itertools.repeat(None, k)]


def random_email(prefix=(2, 8), domain=(5, 20), sufix=(2, 4)):
    """

    :return:
    """
    l = 'abcdefghijklmnopqrstuvwxyz'
    n = '1234567890'
    p = random.randrange(*prefix)
    d = random.randrange(*domain)
    s = random.randrange(*sufix)

    return '{}@{}.{}'.format("".join(sample_wr(l + n, p)), "".join(sample_wr(l + n, d)), "".join(sample_wr(l, s)))
