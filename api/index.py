import os
import re
import time
import traceback
import uuid
from datetime import datetime, timedelta
from html import escape

import bcrypt
import cloudinary
import cloudinary.uploader
import pymongo
import requests
from bson import ObjectId
from flask import Flask, abort, render_template, request, session, redirect, url_for
from flask_caching import Cache
from flask_wtf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from utils import (
    gen_posts_pipeline, supported_languages, time_zones, Posts,
    PasswordSettingsForm, PictureSettingsForm, AccountSettingsForm, LoginForm, ActionsForm, DoingForm, RegistrationForm,
    send_confirmation_link, User, ThemeForm, DesignForm
)

config = {
    "DEBUG": True,  # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300,
    "MAX_CONTENT_LENGTH": 5 * 1024 * 1024,
    "SECRET_KEY": "owler"
}
CF_SECRET_KEY = os.environ.get('CF_SECRET_KEY', '')
SITE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

app = Flask(__name__)

app.config.from_mapping(config)
cache = Cache(app)

# setup here
cloudinary.config(
    cloud_name="dlyl1nlco",
    api_key="337385641594723",
    api_secret="hSrlppiKUvrobg-_PgZPxgOGMj4"
)

mongo_client = pymongo.MongoClient(os.environ.get('MONGO_URI', 'mongodb://localhost:27017/'))
db = mongo_client.get_database(os.environ.get('MONGO_DB', 'lwitter'))
url_pattern = re.compile(r'(https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9('
                         r')@:%_\+.~#?&//=]*))')
mention_pattern = re.compile(r'(?<=[\s,.!?])@(\w+)|^@(\w+)')
users = db.users
verification = db.verification
counters = db.counters
posts = db.posts
favorites = db.favorites
following = db.following
timestamp = db.timestamp
page_cache = {}

csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)

with app.app_context():
    timestamp.drop()


@app.template_global()
def im_following(user_id):
    myself = me()
    if not myself:
        return False
    return following.count_documents({"following": user_id, "follower": myself["_id"]}) > 0


@app.template_global()
def date_to_text(dt):
    now = datetime.utcnow()
    diff = now - dt

    if diff < timedelta(seconds=5):
        return "less than 5 seconds ago"
    elif diff < timedelta(seconds=30):
        return "half a minute ago"
    elif diff < timedelta(minutes=1):
        return "less than a minute ago"
    elif diff < timedelta(minutes=2):
        return "2 minutes ago"
    elif diff < timedelta(hours=1):
        minutes_ago = diff.seconds // 60
        return f"{minutes_ago} minutes ago"
    elif diff < timedelta(days=1):
        hours_ago = diff.seconds // 3600
        return f"{hours_ago} hours ago"
    elif diff < timedelta(days=7):
        return f"this week"
    elif diff < timedelta(weeks=4):
        return f"this month"
    elif diff < timedelta(weeks=48):
        return f"this year"
    elif diff < timedelta(days=1):
        return dt.strftime("%d/%m/%Y %H:%M (UTC)")


@app.template_filter('to_html')
def to_html(input_text: str) -> str:
    input_text = escape(input_text)

    output_text = url_pattern.sub(r'<a href="\1">\1</a>', input_text)
    return mention_pattern.sub(r'<a href="/\1\2">@\1\2</a>', output_text)


@app.template_global()
def alert():
    if 'alert' in session:
        content = session['alert']
        session.pop('alert')
        return content
    return None


@app.template_global()
def me():
    if "id" in session:
        if not cache.get(session["id"]):
            user = reload_cache()
            return user
        return cache.get(session["id"])
    return None


@app.context_processor
def processor():
    processor_dict = dict(
        picture_settings_form=PictureSettingsForm(),
        password_settings_form=PasswordSettingsForm(),
        registration_form=RegistrationForm(),
        actions_form=ActionsForm(),
        login_form=LoginForm(),
        theme_form=ThemeForm(),
        design_form=DesignForm(),
        supported_languages=supported_languages,
        time_zones=time_zones,
        max_content_length=app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
    )

    return processor_dict


def get_ip():
    headers_list = request.headers.getlist("HTTP_X_FORWARDED_FOR")
    http_x_real_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_address = headers_list[0] if headers_list else http_x_real_ip
    return ip_address


def get_next_sequence(name):
    ret = counters.find_one_and_update(
        filter={'_id': name},
        update={'$inc': {'seq': 10}},
        return_document=True
    )

    if ret is None:
        counters.insert_one({'_id': name, 'seq': 10})
        ret = {'seq': 10}

    return ret['seq']


def validate(token):
    try:
        signed_token = serializer.loads(token)
        if not timestamp.find_one({"_id": signed_token}):
            timestamp.insert_one({"_id": signed_token})
            return True
        else:
            return False
    except BadSignature:
        return False


def generate_token():
    return serializer.dumps(time.time())


def reload_cache():
    user_id = ObjectId(session["id"])
    user = users.find_one({"_id": user_id})
    if user is None:
        session.pop('id')
        return None
    most_recent_post = posts.find_one(
        {"user_id": user_id},
        sort=[("_id", -1)]
    )
    if most_recent_post:
        user['last_update'] = most_recent_post
    if user['following_count'] > 0:
        list_following = list(
            following.aggregate(
                [
                    {
                        '$match': {
                            'follower': user['_id']
                        }
                    },
                    {
                        '$lookup': {
                            'from': 'users',
                            'localField': 'following',
                            'foreignField': '_id',
                            'as': 'users'
                        }
                    },
                    {
                        '$unwind': '$users'
                    },
                    {
                        '$project': {
                            '_id': '$users._id',
                            'name': '$users.name',
                            'screen_name': '$users.screen_name',
                            'profile_image_https': '$users.profile_image_https'
                        }
                    },
                    {
                        '$limit': 10
                    }
                ]
            )
        )
        user['following'] = list_following
    else:
        following.insert_one({
            "following": user["_id"],
            "follower": user["_id"]
        })
        following.insert_one({
            "following": ObjectId('65354165a9fd5b661a33732a'),
            "follower": user["_id"]
        })
        users.find_one_and_update(
            {
                "_id": user["_id"]
            },
            {
                "$inc": {
                    "following_count": 2
                }
            }
        )
        user['following_count'] = 2
    cache.set(session["id"], user)
    return user


@app.route('/', methods=['GET'])
def index():
    doing_form = DoingForm(enigma=generate_token())
    args = {
        'limit': 10
    }
    if 'id' in session:
        user_id = ObjectId(session["id"])
        if "after" in request.args:
            if not request.args.get("after").isdigit():
                abort(400)
        if 'after' in request.args:
            result = list(
                following.aggregate(
                    [
                        {
                            '$match': {
                                'follower': user_id
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'posts',
                                'localField': 'following',
                                'foreignField': 'user_id',
                                'as': 'posts'
                            }
                        },
                        {
                            '$unwind': '$posts'
                        },
                        {
                            '$replaceRoot': {
                                'newRoot': '$posts'
                            }
                        },
                        {
                            '$match': {
                                '_id': {
                                    '$lt': int(request.args.get('after')),
                                },
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'users',
                                'localField': 'user_id',
                                'foreignField': '_id',
                                'as': 'user'
                            }
                        },
                        {
                            '$unwind': {
                                'path': '$user'
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'favorites',
                                'let': {
                                    'post_id': '$_id',
                                    'user_id': user_id
                                },
                                'pipeline': [
                                    {
                                        '$match': {
                                            '$expr': {
                                                '$and': [
                                                    {
                                                        '$eq': [
                                                            '$user_id', '$$user_id'
                                                        ]
                                                    }, {
                                                        '$eq': [
                                                            '$post_id', '$$post_id'
                                                        ]
                                                    }
                                                ]
                                            }
                                        }
                                    }, {
                                        '$project': {
                                            'favorite': {
                                                '$literal': True
                                            }
                                        }
                                    }
                                ],
                                'as': 'favoriteMatches'
                            }
                        },
                        {
                            '$addFields': {
                                'favoriteMatch': {
                                    '$cond': {
                                        'if': {
                                            '$gt': [
                                                {
                                                    '$size': '$favoriteMatches'
                                                }, 0
                                            ]
                                        },
                                        'then': True,
                                        'else': False
                                    }
                                }
                            }
                        },
                        {
                            '$project': {
                                'content': 1,
                                'user_id': 1,
                                'timestamp': 1,
                                'origin': 1,
                                'profile_image_https': '$user.profile_image_https',
                                'screen_name': '$user.screen_name',
                                'name': '$user.name',
                                'favorite': '$favoriteMatch'
                            }
                        },
                        {
                            '$sort': {
                                '_id': -1
                            }
                        },
                        {'$limit': 10}
                    ]
                )
            )
        else:
            result = list(
                following.aggregate(
                    [
                        {
                            '$match': {
                                'follower': user_id
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'posts',
                                'localField': 'following',
                                'foreignField': 'user_id',
                                'as': 'posts'
                            }
                        },
                        {
                            '$unwind': '$posts'
                        },
                        {
                            '$replaceRoot': {
                                'newRoot': '$posts'
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'users',
                                'localField': 'user_id',
                                'foreignField': '_id',
                                'as': 'user'
                            }
                        },
                        {
                            '$unwind': {
                                'path': '$user'
                            }
                        },
                        {
                            '$lookup': {
                                'from': 'favorites',
                                'let': {
                                    'post_id': '$_id',
                                    'user_id': user_id
                                },
                                'pipeline': [
                                    {
                                        '$match': {
                                            '$expr': {
                                                '$and': [
                                                    {
                                                        '$eq': [
                                                            '$user_id', '$$user_id'
                                                        ]
                                                    }, {
                                                        '$eq': [
                                                            '$post_id', '$$post_id'
                                                        ]
                                                    }
                                                ]
                                            }
                                        }
                                    }, {
                                        '$project': {
                                            'favorite': {
                                                '$literal': True
                                            }
                                        }
                                    }
                                ],
                                'as': 'favoriteMatches'
                            }
                        },
                        {
                            '$addFields': {
                                'favoriteMatch': {
                                    '$cond': {
                                        'if': {
                                            '$gt': [
                                                {
                                                    '$size': '$favoriteMatches'
                                                }, 0
                                            ]
                                        },
                                        'then': True,
                                        'else': False
                                    }
                                }
                            }
                        },
                        {
                            '$project': {
                                'content': 1,
                                'user_id': 1,
                                'timestamp': 1,
                                'origin': 1,
                                'profile_image_https': '$user.profile_image_https',
                                'screen_name': '$user.screen_name',
                                'name': '$user.name',
                                'favorite': '$favoriteMatch'
                            }
                        },
                        {
                            '$sort': {
                                '_id': -1
                            }
                        },
                        {'$limit': 10}
                    ]
                )
            )

        return render_template('home.html', doing_form=doing_form, posts=result)
    else:
        args['match'] = {
            "$match": {
                "user.protected": False,
            }
        }
        result = list(
            posts.aggregate(
                gen_posts_pipeline(
                    **args
                )
            )
        )
        return render_template('index.html', posts=result)


@app.route('/<screen_name>', endpoint='post_profile', methods=['POST'])
@app.route('/<string:screen_name>/statuses/<int:post_id>', endpoint='post_statuses', methods=['POST'])
@app.route('/public_timeline', endpoint='post_public_timeline', methods=['POST'])
@app.route('/favorites/top10', endpoint='post_user_favorites', methods=['POST'])
@app.route('/', methods=['POST'], endpoint='post_index')
def post_index(screen_name=None, post_id=None):
    my_user_id = ObjectId(session["id"])
    if users.count_documents({'_id': my_user_id}, limit=1) < 1:
        session['alert'] = "Couldn't find your user, try signing out and in again."
    endpoint = request.endpoint[5:]

    doing_form = DoingForm()
    if doing_form.validate_on_submit() and validate(doing_form.enigma.data):
        myself = me()
        post_id = get_next_sequence('post_id')
        post_data = {
            "_id": post_id,
            "user_id": ObjectId(session['id']),
            "content": doing_form.text_content.data,
            "origin": "web",
            "timestamp": datetime.utcnow()
        }
        try:
            bson = Posts(**post_data).to_bson()

            post = posts.insert_one(bson)
            if post:
                my_user = users.find_one_and_update(
                    {
                        "_id": my_user_id
                    },
                    {
                        "$inc": {
                            "updates_count": 1
                        }
                    }
                )
                if my_user:
                    reload_cache()
                    return redirect(url_for('index'))
        except ValidationError as e:
            error_messages = e.errors()
            error_messages = [f"{field['loc'][0]}: {field['msg']}" for field in error_messages]
            alert = "\n".join(error_messages)
            session['alert'] = alert
            return redirect(url_for('index'))
    action_form = ActionsForm()

    if action_form.validate_on_submit():
        if not action_form.post_id.data.isdigit():
            abort(400)
        posted_id = int(action_form.post_id.data)
        if 'star' in request.form:
            if favorites.find_one({
                "user_id": my_user_id,
                "post_id": posted_id,
            }):
                favorite_deleted = favorites.delete_one(
                    {
                        "user_id": my_user_id,
                        "post_id": int(request.form.get('post_id')),
                    }
                )

                favorite_count_decreased = posts.find_one_and_update(
                    {
                        "_id": posted_id
                    },
                    {
                        "$inc": {
                            "favorites_count": -1
                        }
                    }
                )
                favorite_count_decreased_user = users.find_one_and_update(
                    {
                        "_id": my_user_id
                    },
                    {
                        "$inc": {
                            "favorites_count": -1
                        }
                    }
                )
                if (
                        not favorite_count_decreased or not favorite_count_decreased_user or favorite_deleted.deleted_count < 1
                ):
                    abort(403)
            else:
                favorite_inserted = favorites.insert_one({
                    "user_id": my_user_id,
                    "post_id": posted_id,
                })

                favorite_count_increased = posts.find_one_and_update(
                    {
                        "_id": posted_id
                    },
                    {
                        "$inc": {
                            "favorites_count": 1
                        }
                    }
                )
                favorite_count_increased_user = users.find_one_and_update(
                    {
                        "_id": my_user_id
                    },
                    {
                        "$inc": {
                            "favorites_count": 1
                        }
                    }
                )
                if (
                        not favorite_inserted.inserted_id or
                        not favorite_count_increased_user or
                        not favorite_count_increased
                ):
                    abort(404)
        elif 'trash' in request.form:
            deleted_post = posts.delete_one({
                "_id": posted_id,
                "user_id": my_user_id
            })

            if deleted_post.deleted_count == 1:

                favorites.delete_many(
                    {
                        "post_id": posted_id
                    }
                )
                updates_count_decreased = users.find_one_and_update(
                    {
                        "_id": my_user_id
                    },
                    {
                        "$inc": {
                            "updates_count": -1
                        }
                    }
                )
                if not updates_count_decreased:
                    abort(403)
                reload_cache()
            else:
                abort(403)
            if endpoint == 'statuses':
                return redirect(url_for('index'))

    if post_id:
        return redirect(url_for(endpoint, screen_name=screen_name, post_id=post_id))
    if screen_name:
        return redirect(url_for(endpoint, screen_name=screen_name))
    return redirect(url_for(endpoint))


# @app.route('/secret/login/<sid>')
# def secret(sid):
#     print(sid)
#     session['id'] = sid
#     reload_cache()
#     return redirect(url_for('index'))


@app.route('/favorites/top10')
def top10():
    if 'id' not in session:
        return redirect(url_for('login'))
    args = {
        "match": {
            "$match": {
                "user.protected": False,
            }
        },
        "sort": {
            "$sort": {"favorites_count": -1}
        },
        "limit": 10
    }
    if 'id' in session:
        args['user_id'] = ObjectId(session['id'])
    result = list(
        posts.aggregate(
            gen_posts_pipeline(
                **args
            )
        )
    )
    return render_template(
        'top10.html',
        posts=result,
        favorites_count=favorites.count_documents({}),
        updates_count=posts.count_documents({})
    )


@app.route('/public_timeline')
def public_timeline():
    if 'id' not in session:
        return redirect(url_for('login'))
    args = {

        "match": {
            "$match": {
                "user.protected": False,
            }
        }
    }

    if 'id' in session:
        args['user_id'] = ObjectId(session['id'])
    result = list(
        posts.aggregate(
            gen_posts_pipeline(
                **args
            )
        )
    )
    return render_template(
        'public_timeline.html',
        posts=result,
        users_count=users.count_documents({}),
        favorites_count=favorites.count_documents({}),
        updates_count=posts.count_documents({})
    )


@app.route('/create', methods=['GET'])
def create():
    return render_template('create.html')


@app.route('/create', methods=['POST'])
def post_create():
    form = RegistrationForm()

    if form.validate_on_submit():
        if request.form:
            token = request.form.get('cf-turnstile-response')
            ip = get_ip()

            data = {
                'secret': CF_SECRET_KEY,
                'response': token,
                'remoteip': ip
            }
            # Captcha disabled

            # result = requests.post(SITE_VERIFY_URL, data=data)

            # outcome = result.json()
            # if not outcome.get('success'):
            #     session['alert'] = "Invalid captcha!"
            #     return redirect(url_for('create'))
            password = form.password.data

            email = form.email.data
            lang = request.accept_languages.best_match(supported_languages)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            upload_result = None
            if form.profile_image.data and form.profile_image.data.filename != '':
                upload_result = cloudinary.uploader.upload(form.profile_image.data, width=48, height=48, crop="fill")

            user_data = {
                "name": form.name.data,
                "screen_name": form.screen_name.data,
                "password": hashed_password,
                "email": email,
                "time_zone": form.time_zone.data,
                "lang": lang,
                "protected": form.protected.data,
                "profile_image_https":
                    upload_result.get('secure_url') if upload_result and upload_result.get('url') is not None
                    else None,
                "profile_image_http":
                    upload_result.get('url') if upload_result and upload_result.get('url') is not None
                    else None,
                "alpha": True
            }

            try:
                user = User(**user_data)
            except ValidationError as e:
                error_messages = e.errors()
                error_messages = [f"{field['loc'][0]}: {field['msg']}" for field in error_messages]
                alert = " - ".join(error_messages)
                session['alert'] = alert
                return redirect(url_for('create'))
            try:
                data = users.insert_one(user.to_bson())
            except DuplicateKeyError:
                session['alert'] = f"@{form.screen_name.data} already been used!"
                return redirect(url_for('create'))
            following.insert_one({
                "following": data.inserted_id,
                "follower": data.inserted_id
            })
            following.insert_one({
                "following": ObjectId('65354165a9fd5b661a33732a'),
                "follower": data.inserted_id
            })
            users.find_one_and_update(
                {
                    "_id": data.inserted_id
                },
                {
                    "$inc": {
                        "following_count": 2
                    }
                }
            )
            users.find_one_and_update(
                {
                    "_id": ObjectId('65354165a9fd5b661a33732a')
                },
                {
                    "$inc": {
                        "followers_count": 1
                    }
                }
            )
            code = str(uuid.uuid4())
            verify = verification.insert_one({
                "email": email,
                "user_id": data.inserted_id,
                "code": code
            })

            url = f"{request.url_root}{url_for('confirm_email', code=code)}"

            if data and verify and send_confirmation_link(
                    username=user_data['screen_name'],
                    email=email,
                    url=url
            ):
                # Disabled: email verification
                # session['email'] = email
                # return redirect(url_for('verify'))
                return redirect(url_for('login'))

            abort(403)
    errors = form.errors
    session['alert'] = errors
    return redirect(url_for('create'))


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def post_login():
    form = LoginForm()

    if form.validate_on_submit():
        username_or_email = form.username_or_email.data
        password = form.password.data
        # remember_me = form.remember_me.data
        user_found = users.find_one({"email": username_or_email})

        if not user_found:
            user_found = users.find_one({"screen_name": username_or_email})

        if user_found:
            real_password = user_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), real_password):
                session["id"] = str(user_found["_id"])
                return redirect(url_for('index'))
            else:
                session['alert'] = "Invalid login credentials!"
                return redirect(url_for('login'))
        session['alert'] = "Couldn't find your user"

        return redirect(url_for('login'))
    session['alert'] = "Invalid login credentials!"
    return redirect(url_for('login'))


@app.route('/verify', methods=['GET'])
def verify():
    if 'email' not in session:
        abort(404)
    return render_template(
        'upgrading.html',
        title="owler / verify",
        subtitle="Verify your email address",
        description=f"Check your email address ({session['email']}) and follow the instructions "
                    f"there to have access to all the features on your account."
    )


@app.route('/settings/account', endpoint='account_settings', methods=['GET'])
@app.route('/settings/password', endpoint='password_settings', methods=['GET'])
@app.route('/settings/picture', endpoint='picture_settings', methods=['GET'])
@app.route('/settings/design', endpoint='design_settings', methods=['GET'])
@app.route('/settings/theme', endpoint='theme_settings', methods=['GET'])
def settings():
    if "id" in session:
        acf = AccountSettingsForm()
        if me() is not None:
            acf = AccountSettingsForm(**me())
        return render_template('settings.html',
                               page=request.endpoint,
                               account_settings_form=acf)
    return redirect(url_for('index'))


@app.route('/settings/account', methods=['POST'])
def post_account_settings():
    form = AccountSettingsForm()

    if form.validate_on_submit():
        query = [
            {
                "_id": ObjectId(session["id"])
            },
            {
                "$set": {
                    **form.data
                }
            }
        ]
        try:
            if users.update_one(
                    *query
            ):
                reload_cache()
                return redirect(url_for('account_settings'))
        except DuplicateKeyError as e:
            session['alert'] = 'Username already taken!'
            return redirect(url_for('account_settings'))

    errors = form.errors
    session['alert'] = errors
    return redirect(url_for('account_settings'))


@app.route('/settings/picture', methods=['POST'])
def post_picture_settings():
    form = PictureSettingsForm()

    if form.validate_on_submit():
        user_profile_picture = form.profile_image.data
        user_found = me()
        if user_found:
            upload_result = cloudinary.uploader.upload(user_profile_picture, width=48, height=48, crop="fill")

            if users.update_one(
                    {
                        "_id": user_found['_id']
                    },
                    {
                        "$set": {
                            "profile_image_https":
                                upload_result.get('secure_url') if upload_result and upload_result.get(
                                    'url') is not None
                                else None,
                            "profile_image_http":
                                upload_result.get('url') if upload_result and upload_result.get('url') is not None
                                else None,
                        }
                    }
            ):
                return redirect(url_for('profile', screen_name=user_found['screen_name']))
            else:
                session['alert'] = "Couldn't Find Your User"
                return redirect(url_for('picture_settings'))
        session['alert'] = "Something went wrong"
        return redirect(url_for('picture_settings'))
    errors = form.errors
    session['alert'] = errors
    return redirect(url_for('picture_settings'))


@app.route('/settings/password', methods=['POST'])
def post_password_settings():
    form = PasswordSettingsForm()

    if form.validate_on_submit():

        old_password = form.old_password.data
        new_password = form.password.data

        password_confirmation = form.password_confirmation.data
        if password_confirmation != new_password:
            session['alert'] = "Both passwords should be equal!"
            return redirect(url_for('password_settings'))
        # remember_me = form.remember_me.data
        user_found = me()
        if user_found:
            real_password = user_found['password']

            if bcrypt.checkpw(old_password.encode('utf-8'), real_password):
                if users.update_one(
                        {
                            "_id": user_found['_id']
                        },
                        {
                            "$set": {
                                "password": bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                            }
                        }
                ):
                    return redirect(url_for('password_settings'))
            else:
                session['alert'] = "Invalid Password!"
                return redirect(url_for('password_settings'))
            session['alert'] = "Invalid login credentials!"
        return redirect(url_for('password_settings'))
    errors = form.errors
    session['alert'] = f"Invalid login credentials! ({errors})"
    return redirect(url_for('password_settings'))


@app.route('/settings/design', methods=['POST'])
def post_design_settings():
    session['alert'] = "This feature is not implemented right now, wait for updates."
    return redirect(url_for('design_settings'))


@app.route('/settings/theme', methods=['POST'])
def post_theme_settings():
    session['alert'] = "This feature is not implemented right now, wait for updates."
    return redirect(url_for('theme_settings'))


@app.route('/<string:screen_name>/statuses/<int:post_id>', methods=['GET'])
def statuses(screen_name, post_id):
    args = {
        "match": {
            "$match": {
                "_id": post_id,
                "user.screen_name": screen_name
            }
        },
        "limit": 1
    }

    if 'id' in session:
        args['user_id'] = ObjectId(session['id'])

    result = list(
        posts.aggregate(
            gen_posts_pipeline(
                **args
            )
        )
    )

    if not result:
        abort(404)  # Return a 404 error if there are no results
    return render_template('statuses.html', post=result[0])


@app.route('/<string:screen_name>/favorites', methods=['GET'])
def user_favorites(screen_name):
    my_user = me()
    if not my_user:
        return redirect(url_for('login'))
    user = users.find_one({"screen_name": screen_name})
    if not user:
        abort(404)
    if user['protected'] and my_user and following.find_one({
        "following": user["_id"],
        "follower": my_user["_id"]
    }):
        user['protected'] = False
    list_posts = list(
        favorites.aggregate(
            [
                {
                    '$match': {
                        'user_id': user['_id']
                    }
                },
                {
                    '$lookup': {
                        'from': 'posts',
                        'localField': 'post_id',
                        'foreignField': '_id',
                        'as': 'post'
                    }
                },
                {
                    '$unwind': '$post'
                },
                {
                    '$lookup': {
                        'from': 'users',
                        'localField': 'post.user_id',
                        'foreignField': '_id',
                        'as': 'user_info'
                    }
                },
                {
                    '$unwind': '$user_info'
                },
                {
                    '$project': {
                        'favorite_id': '$_id',
                        '_id': '$post_id',
                        'user_id': '$post.user_id',
                        'content': '$post.content',
                        'origin': '$post.origin',
                        'favorites_count': '$post.favorites_count',
                        'replies_count': '$post.replies_count',
                        'timestamp': '$post.timestamp',
                        'screen_name': '$user_info.screen_name',
                        'name': '$user_info.name',
                        'profile_image_https': '$user_info.profile_image_https'
                    }
                },
                {
                    '$limit': 10
                },
                {
                    "$sort": {"favorite_id": -1}
                }
            ]
        )
    )
    if user['following_count'] > 0:
        list_following = list(
            following.aggregate(
                [
                    {
                        '$match': {
                            'follower': user['_id']
                        }
                    },
                    {
                        '$lookup': {
                            'from': 'users',
                            'localField': 'following',
                            'foreignField': '_id',
                            'as': 'users'
                        }
                    },
                    {
                        '$unwind': '$users'
                    },
                    {
                        '$project': {
                            '_id': '$users._id',
                            'name': '$users.name',
                            'screen_name': '$users.screen_name',
                            'profile_image_https': '$users.profile_image_https'
                        }
                    },
                    {
                        '$limit': 10
                    }
                ]
            )
        )
        return render_template('profile.html', following=list_following, user=user, tab_previous=False,
                               posts=list_posts)

    else:
        return render_template('profile.html', user=user, tab_previous=False, posts=list_posts)


@app.route('/<string:screen_name>', methods=['GET'])
def profile(screen_name):
    my_user = me()
    user = users.find_one({"screen_name": screen_name})
    if not user:
        abort(404)
    args = {"match": {
        "$match": {
            "user.screen_name": screen_name
        }
    }}

    if 'id' in session:
        args['user_id'] = ObjectId(session['id'])

    list_posts = list(
        posts.aggregate(
            gen_posts_pipeline(
                **args
            )
        )
    )
    if user['protected'] and my_user and following.find_one({
        "following": user["_id"],
        "follower": my_user["_id"]
    }):
        user['protected'] = False
    if user['following_count'] > 0:

        list_following = list(
            following.aggregate(
                [
                    {
                        '$match': {
                            'follower': user['_id']
                        }
                    },
                    {
                        '$lookup': {
                            'from': 'users',
                            'localField': 'following',
                            'foreignField': '_id',
                            'as': 'users'
                        }
                    },
                    {
                        '$unwind': '$users'
                    },
                    {
                        '$project': {
                            '_id': '$users._id',
                            'name': '$users.name',
                            'screen_name': '$users.screen_name',
                            'profile_image_https': '$users.profile_image_https'
                        }
                    },
                    {
                        '$limit': 10
                    }
                ]
            )
        )
        return render_template('profile.html', following=list_following, user=user, tab_previous=True, posts=list_posts)
    else:
        return render_template('profile.html', user=user, tab_previous=True, posts=list_posts)


@app.route('/<screen_name>/follow', methods=['GET'])
def follow(screen_name):
    my_user = me()
    if not my_user:
        return redirect(url_for('index'))
    user = users.find_one({"screen_name": screen_name})
    if not user or user['protected']:
        abort(404)

    if following.find_one({
        "following": user["_id"],
        "follower": my_user["_id"]
    }):
        # Unfollow
        following.delete_one({
            "following": user["_id"],
            "follower": my_user["_id"]
        })
        users.find_one_and_update(
            {
                "_id": my_user["_id"]
            },
            {
                "$inc": {
                    "following_count": -1
                }
            }
        )
        users.find_one_and_update(
            {
                "_id": user["_id"]
            },
            {
                "$inc": {
                    "followers_count": -1
                }
            }
        )
    else:
        following.insert_one({
            "following": user["_id"],
            "follower": my_user["_id"]
        })
        users.find_one_and_update(
            {
                "_id": my_user["_id"]
            },
            {
                "$inc": {
                    "following_count": 1
                }
            }
        )
        users.find_one_and_update(
            {
                "_id": user["_id"]
            },
            {
                "$inc": {
                    "followers_count": 1
                }
            }
        )
    reload_cache()
    return redirect(url_for('profile', screen_name=screen_name))


@app.route('/confirm/<uuid:code>')
def confirm_email(code):
    user_found = verification.find_one({'code': str(code)})
    if user_found:
        if 'email' in session:
            session.pop('email')
        session["id"] = str(user_found['user_id'])
        if users.update_one(
                {
                    "_id": user_found['user_id']
                },
                {
                    "$set": {
                        "verified_email": True,
                        "alpha": True
                    }
                }
        ):
            result = verification.delete_one({"_id": user_found['_id']})
            if result:
                return redirect(url_for('index'))
    abort(404)


@app.route('/sign_out')
def sign_out():
    session.pop('id')
    return redirect(url_for('index'))

# Disabled: blog doesn't exist
# @app.route('/blog')
# def blog():
#     return redirect("https://owler.blogspot.com/", code=302)


@app.route('/help/aboutus')
def aboutus():
    if 'faq.html' in page_cache:
        return page_cache['aboutus.html']
    template = render_template('aboutus.html')
    return template


@app.route('/faq')
def faq():
    if 'faq.html' in page_cache:
        return page_cache['faq.html']
    template = render_template('faq.html')
    return template


@app.route('/tos')
def tos():
    if 'tos.html' in page_cache:
        return page_cache['tos.html']
    template = render_template('tos.html')
    return template


@app.errorhandler(404)
def page_forbidden(e):
    return '404', 404


@app.errorhandler(403)
def forbidden(e):
    return '403', 403


@app.errorhandler(400)
def bad_request(e):
    return '400', 400


@app.errorhandler(429)
def too_many_requests(e):
    return '429', 429


@app.errorhandler(Exception)
def exception_handler(error):
    traceback.print_exc()
    return "report this error to email@email.com", 400

# @app.after_request
# def after_request_func(response):
#     # file1 = open('test' + '/' + 'a' + request.path.replace('/', '-') + '.html', 'wb')
#     # file1.write(response.data)
#     # file1.close()
#     print(session)
#     return response
