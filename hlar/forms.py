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

class TargetForm(ModelForm):
    """ターゲットのフォーム"""
    class Meta:
        model = Target
        fields = ('content_name', 'vuforia_target_id', 'view_count', )


# class SignUpForm(UserCreationForm):
class SignUpForm(UserCreationForm):
    # first_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    # last_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    email = forms.EmailField(max_length=254, help_text='必須項目')

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2' )


class UserForm(UserChangeForm):
    """user form"""

    password = forms.CharField(
        widget=forms.PasswordInput(),
        min_length=8,
        label="パスワード(変更時のみ入力して下さい)",
        required=False,
        )

    # is_active = forms.ModelChoiceField(
    #     queryset={'all':'all', 'key':'value'},
    #     widget=forms.RadioSelect,
    #     label="アクティブ",
    # )


    # license = forms.ModelMultipleChoiceField(
    #     label="資格",
    #     queryset=License.objects.all(),
    #     widget=forms.CheckboxSelectMultiple,  # 複数選択チェックボックスへ変更。デフォルトはSelectMultiple
    # )
    #
    # permission = forms.ModelChoiceField(
    #     label="偉さ",
    #     queryset=Permission.objects.all(),
    #     widget=forms.RadioSelect,  # ラジオに変更。デフォルトはSelect
    #     empty_label=None,
    # )
    #
    # gendar = forms.ChoiceField(
    #     label="性別",
    #     choices=GENDER_CHOICES,
    #     widget=forms.RadioSelect,  # ラジオに変更
    # )
    #
    # login = forms.ChoiceField(
    #     label="ログイン可能時間",
    #     choices=TIME_CHOICES,
    #     widget=forms.RadioSelect,  # ラジオに変更
    # )


    class Meta:
        model = User
        fields = ('id','email', 'username', 'password', )

    def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            for field in self.fields.values():
                field.widget.attrs["class"] = "form-control"
                field.widget.attrs["style"] = "width:200px"


    # def user_edit(self):
    #         assert(self.is_valid())
    #         user = self.cleaned_data['user']
    #         user.email =
    #         user.save()


class LoginForm(AuthenticationForm):
    username = forms.CharField(label="ユーザー名", max_length=30,
                               widget=forms.TextInput(attrs={'class': 'form-control', 'name': 'username'}))
    password = forms.CharField(label="パスワード", max_length=30,
                               widget=forms.PasswordInput(attrs={'class': 'form-control', 'name': 'password'}))

# class RFPAuthForm(AuthenticationForm):
#     username = forms.CharField(widget=TextInput(attrs={'class': 'span2','placeholder': 'Email'}))
#     password = forms.CharField(widget=PasswordInput(attrs={'class': 'span2','placeholder':'Password'}))
