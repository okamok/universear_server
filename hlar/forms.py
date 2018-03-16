from django.forms import ModelForm
from hlar.models import Target

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import UserChangeForm
# from django.contrib.auth.models import User
from hlar.models import User
# from django.contrib.auth.hashers import make_password

from django.contrib.auth.forms import AuthenticationForm
from django.forms.widgets import PasswordInput, TextInput
from registration.forms import RegistrationForm, RegistrationFormTermsOfService, RegistrationFormUniqueEmail


class TargetForm(ModelForm):
    """ターゲットのフォーム"""
    class Meta:
        model = Target
        fields = ('content_name', 'vuforia_target_id', 'view_count', )



class CustomRegistrationForm(RegistrationForm):
    email = forms.EmailField(
        max_length=254,
        # help_text='必須項目'
        widget=TextInput(attrs={'class': '','placeholder': 'Email'})
    )

    password2 = forms.CharField(
        max_length=254,
        widget=forms.PasswordInput(),
        # help_text='必須項目!',
        label = 'パスワードの確認'
    )

    class Meta:
        model = User

        widgets = {
            'username' : forms.TextInput(attrs = {'placeholder': 'Username'}),
        }

        fields = ('username', 'email', 'password1', 'password2' )


# class SignUpForm(UserCreationForm):
class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='必須項目!!!')

    class Meta:
        model = User

        widgets = {
            'username' : forms.TextInput(attrs = {'placeholder': 'Username'}),
            'email'    : forms.TextInput(attrs = {'placeholder': 'E-Mail'}),
        }

        fields = ('username', 'email', 'password1', 'password2' )

class UserForm(UserChangeForm):
    """user form"""

    password = forms.CharField(
        widget=forms.PasswordInput(),
        min_length=8,
        label="パスワード",
        required=False,
        )

    class Meta:
        model = User
        fields = ('id','email', 'username', 'password', )

    def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            for field in self.fields.values():
                field.widget.attrs["class"] = "form-control"
                field.widget.attrs["style"] = "width:100%"

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="ユーザー名", max_length=30,
                               widget=forms.TextInput(attrs={'class': 'form-control', 'name': 'username'}))
    password = forms.CharField(label="パスワード", max_length=30,
                               widget=forms.PasswordInput(attrs={'class': 'form-control', 'name': 'password'}))
