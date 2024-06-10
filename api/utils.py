import datetime
import os
import typing
from typing import Any, Callable

from bson import ObjectId
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from pydantic import StringConstraints, BaseModel, Field
from pydantic_core import core_schema
from typing_extensions import Annotated
from wtforms import StringField, TextAreaField, SubmitField, HiddenField, PasswordField, BooleanField, SelectField, \
    ColorField
from wtforms.validators import DataRequired, Length, Email, URL, Optional, Regexp, EqualTo

allowed_image_mime_types = {'image/gif', 'image/jpeg', 'image/pjpeg', 'image/png'}

supported_languages = ["en", "pt-BR", "global"]
trusted_tlds = ["com", "org", "net", "site"]

time_zones = [
    ("Hawaii", "(GMT-10:00) Hawaii"),
    ("Alaska", "(GMT-09:00) Alaska"),
    ("Pacific Time (US & Canada)", "(GMT-08:00) Pacific Time (US & Canada)"),
    ("Arizona", "(GMT-07:00) Arizona"),
    ("Mountain Time (US & Canada)", "(GMT-07:00) Mountain Time (US & Canada)"),
    ("London", "(GMT) London"),
    ("Central Time (US & Canada)", "(GMT-06:00) Central Time (US & Canada)"),
    ("Eastern Time (US & Canada)", "(GMT-05:00) Eastern Time (US & Canada)"),
    ("Atlantic Time (Canada)", "(GMT-04:00) Atlantic Time (Canada)"),
    ("Brasilia", "(GMT-03:00) Brasilia"),
    ("Greenland", "(GMT-03:00) Greenland"),
    ("Central European Time", "(GMT+01:00) Central European Time"),
    ("Eastern European Time", "(GMT+02:00) Eastern European Time"),
    ("Moscow", "(GMT+03:00) Moscow"),
    ("India", "(GMT+05:30) India"),
    ("China", "(GMT+08:00) China"),
    ("Japan", "(GMT+09:00) Japan"),
    ("Sydney", "(GMT+11:00) Sydney")
]


class ThemeForm(FlaskForm):
    theme = SelectField('Theme', choices=["Light", "Dark", "Black"])
    submit = SubmitField('Save Changes')


class DesignForm(FlaskForm):
    text_color = ColorField('Text Color', )
    link_color = ColorField('Link Color')
    sidebar_border_color = ColorField('Sidebar Border Color')
    sidebar_color = ColorField('Sidebar Color')
    background_color = ColorField('Background Color')
    background_image = FileField(
        'Background Image',
        validators=[
            FileAllowed(['jpg', 'png', 'gif'], 'Images only!')
        ]
    )
    submit = SubmitField('Save Changes')


class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(max=50)])
    screen_name = StringField('Username', validators=[DataRequired(), Length(max=30), Regexp('^[a-zA-Z0-9_]+$',
                                                                                             message='Field must contain only letters, numbers, or underscores.')])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    time_zone = SelectField('Time Zone', choices=time_zones)
    protected = BooleanField('Protect my updates')
    password = PasswordField('Create Password', validators=[DataRequired(), Length(min=6)])
    password_confirmation = PasswordField('Retype Password', validators=[DataRequired(), EqualTo('password')])
    profile_image = FileField(
        'Picture',
        validators=[
            FileAllowed(['jpg', 'png', 'gif'], 'Images only!')
        ]
    )
    submit = SubmitField('Continue')


class PasswordSettingsForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[Length(min=6)])
    password = PasswordField('New Password', validators=[Length(min=6)])
    password_confirmation = PasswordField('Retype Password')
    submit = SubmitField('Change Password')


class PictureSettingsForm(FlaskForm):
    profile_image = FileField(
        'Picture',
        validators=[
            FileRequired(),
            FileAllowed(['jpg', 'png', 'gif'], 'Images only!')
        ]
    )
    submit = SubmitField('Change Profile Picture')


class AccountSettingsForm(FlaskForm):
    name = StringField('Full Name', validators=[Length(max=50)])
    screen_name = StringField('Username', validators=[DataRequired(), Length(max=30), Regexp('^[a-zA-Z0-9_]+$',
                                                                                             message='Field must contain only letters, numbers, or underscores.')])
    bio = TextAreaField('Bio', validators=[Length(max=280)])
    location = StringField('Location', validators=[Optional(), Length(max=30)])
    website = StringField('Website', validators=[Optional(), URL()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    lang = SelectField('Language', choices=supported_languages)
    time_zone = SelectField('Time Zone', choices=time_zones)
    protected = BooleanField('Protect my updates')
    submit = SubmitField('Save Changes')


class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Sign In')


class ActionsForm(FlaskForm):
    post_id = HiddenField('Post ID', validators=[DataRequired()])


class DoingForm(FlaskForm):
    enigma = HiddenField()
    text_content = TextAreaField('What are you doing?', validators=[DataRequired()], render_kw={"maxlength": "280"})
    submit = SubmitField('Update')


class _ObjectIdPydanticAnnotation:
    # Based on https://docs.pydantic.dev/latest/usage/types/custom/#handling-third-party-types.

    @classmethod
    def __get_pydantic_core_schema__(
            cls,
            _source_type: Any,
            _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_str(input_value: str) -> ObjectId:
            return ObjectId(input_value)

        return core_schema.union_schema(
            [
                # check if it's an instance first before doing any further work
                core_schema.is_instance_schema(ObjectId),
                core_schema.no_info_plain_validator_function(validate_from_str),
            ],
            serialization=core_schema.to_string_ser_schema(),
        )


PydanticObjectId = Annotated[
    ObjectId, _ObjectIdPydanticAnnotation
]


def gen_posts_pipeline(
        match,
        limit=100,
        user_id=None,
        sort=
        {
            "$sort": {"_id": -1}
        }
):
    if user_id:
        return [
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user"
                }
            },

            {
                "$unwind": "$user"
            },

            match,
            {
                "$lookup": {
                    "from": "favorites",
                    "let": {"post_id": "$_id", "user_id": user_id},
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        {"$eq": ["$user_id", "$$user_id"]},
                                        {"$eq": ["$post_id", "$$post_id"]}
                                    ]
                                }
                            }
                        },
                        {
                            "$project": {
                                "favorite": {"$literal": True}
                            }
                        }
                    ],
                    "as": "favoriteMatches"
                }
            },
            {
                "$addFields": {
                    "favoriteMatch": {
                        "$cond": {
                            "if": {"$gt": [{"$size": "$favoriteMatches"}, 0]},
                            "then": True,
                            "else": False
                        }
                    }
                }
            },
            {
                "$project": {
                    "_id": 1,
                    "content": 1,
                    "origin": 1,
                    "timestamp": 1,
                    "favorites_count": 1,
                    "user_id": "$user._id",
                    "name": "$user.name",
                    "screen_name": "$user.screen_name",
                    "profile_image_https": "$user.profile_image_https",
                    "favorite": "$favoriteMatch"
                }
            },
            sort,
            {
                "$limit": limit
            }
        ]
    else:
        return [
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user"
                }
            },

            # Unwind the user_info array created by $lookup (assuming one document per user)
            {
                "$unwind": "$user"
            },

            match,
            # Project the desired fields to the output
            {
                "$project": {
                    "_id": 1,  # Exclude the default _id field
                    "content": 1,
                    "origin": 1,
                    "timestamp": 1,
                    "favorites_count": 1,
                    "name": "$user.name",
                    "screen_name": "$user.screen_name",
                    "profile_image_https": "$user.profile_image_https"
                }
            },
            sort,
            {
                "$limit": limit
            }
        ]


class Posts(BaseModel):
    post_id: int = Field(alias='_id')
    user_id: PydanticObjectId
    content: Annotated[
        str,
        StringConstraints(
            max_length=280,
            min_length=1
        )
    ]
    origin: Annotated[
        str,
        StringConstraints(
            max_length=50,
            min_length=1
        )
    ]
    favorites_count: int = 0
    replies_count: int = 0
    timestamp: datetime.datetime

    def to_bson(self):
        data = self.model_dump(by_alias=True, exclude_none=True)
        return data


class User(BaseModel):
    user_id: typing.Optional[PydanticObjectId] = Field(alias='_id', default=None)
    screen_name: Annotated[
        str,
        StringConstraints(
            max_length=20,
            min_length=1,
            pattern='^[a-zA-Z0-9_]+$'
        )
    ]
    name: Annotated[
        str,
        StringConstraints(
            max_length=50,
            min_length=1
        )
    ]
    password: bytes
    email: str
    time_zone: str = "London"
    protected: bool
    lang: str = 'en'
    profile_image_https: typing.Optional[str] = None
    profile_image_http: typing.Optional[str] = None
    custom_theme: typing.Optional[str] = None
    verified_email: bool = False
    bio: typing.Optional[str] = "Haven't updated yet!"
    location: typing.Optional[str] = None
    website: typing.Optional[str] = None
    following_count: int = 0
    followers_count: int = 0
    favorites_count: int = 0
    direct_messages_count: int = 0
    updates_count: int = 0

    def to_bson(self):
        data = self.model_dump(by_alias=True, exclude_none=True)
        return data


def send_confirmation_link(username, email, url):
    # code for email here
    return True
