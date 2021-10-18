from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed 
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from app.models import User
from flask_babel import _, lazy_gettext as _l
from flask import request

class LoginForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(_l('Password'), validators=[DataRequired(), Length(min=8, max=140)], render_kw={"placeholder": "Password"})
    remember_me = BooleanField(_l('Remember Me'))
    submit = SubmitField(_l('Sign In'))


class RegistrationForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    firstname = StringField(label='First Name', validators=[DataRequired(), Length(min=6,max=20)]) 
    lastname = StringField(label='Last Name', validators=[DataRequired(), Length(min=6,max=20)]) 
    password = PasswordField(_l('Password'), validators=[DataRequired(), Length(min=8, max=140)])
    password2 = PasswordField(_l('Repeat Password'), validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(_l('Register'))

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError(_('Username already exists. Please use a different username.'))

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError(_('Email already exists. Please use a different email address.'))



class EditProfileForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    firstname = StringField(_l('First Name'), validators=[DataRequired(), Length(min=3, max=14)]) 
    lastname = StringField(_l('Last Name'), validators=[DataRequired(), Length(min=3, max=14)])  
    about_me = TextAreaField(_l('About me'), validators=[Length(min=0, max=140)])
    picture=FileField(label='Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField(_l('Submit'))

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError(_('Please use a different username.'))


class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

class PostForm(FlaskForm):
    post = TextAreaField(_l('Say something'), validators=[DataRequired(), Length(min=1, max=600)])
    submit = SubmitField(_l('Submit'))


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))


class ResetPasswordForm(FlaskForm):
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(_l('Request Password Reset'))


class SearchForm(FlaskForm):
    q = StringField(_l('Search'), validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        if 'formdata' not in kwargs:
            kwargs['formdata'] = request.args
        if 'csrf_enabled' not in kwargs:
            kwargs['csrf_enabled'] = False
        super(SearchForm, self).__init__(*args, **kwargs)


class MessageForm(FlaskForm):
    message = TextAreaField(_l('Message'), validators=[
        DataRequired(), Length(min=0, max=140)])
    submit = SubmitField(_l('Submit'))



class AccountUpdateForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired(),Length(min=6,max=20)])
    email = StringField(label='Email', validators=[DataRequired(),Email()])
    picture=FileField(label='Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit=SubmitField(label='Update Account')

class AdminForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    is_admin = BooleanField(_l('Add Admin Privileges'))
    submit = SubmitField(_l('Register as Admin'))



