# forms.py
from wtforms import Form, StringField, SelectField

class DateSearchForm(Form):
    search = StringField('')
