# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.utils.encoding import python_2_unicode_compatible
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
import re
from django.core.validators import EmailValidator
from django.core.validators import validate_email
# from hlar.models import JapaneseEmailValidator


# Create your models here.


class Oauth(models.Model):
    oauth_token = models.CharField(max_length=300, null=True)
    oauth_token_secret = models.CharField(max_length=300, null=True)
    access_token = models.CharField(max_length=300, null=True)
    access_token_secret = models.CharField(max_length=300, null=True)
    id_in_auth_app = models.CharField(max_length=80, null=True)
    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

# class User(models.Model):
#     mail = models.EmailField(max_length=254, null=True)
#     password = models.CharField(max_length=2000, null=True)
#     name = models.CharField(max_length=200, null=True)
#     image_file_name = models.CharField(max_length=200, null=True)
#     oauth = models.ForeignKey(Oauth, on_delete=models.CASCADE, null=True)
#     created_date = models.DateTimeField(auto_now_add=True)
#     modified_date = models.DateTimeField(auto_now=True)
#
#     def clean(self):
#         from django.core.exceptions import ValidationError
#
#         print('self.mail')
#         print(self.mail)
#         if self.mail is None or self.mail == '':
#             raise ValidationError('メールアドレスを入力して下さい。')
#
#         try:
#             # validate_email(request.POST.get("email", ""))
#             validate_email(self.mail)
#         except ValidationError:
#             raise ValidationError('メールアドレスを正しい形式で入力して下さい')







##### user 作り直し
@python_2_unicode_compatible
class UserManager(BaseUserManager):
    # def create_user(self, username, email, password, last_name, first_name):
    def create_user(self, username, email, password=''):
        """
        ユーザ作成

        :param username: ユーザID
        :param email: メールアドレス
        :param password: パスワード
        :return: Userオブジェクト
        """
        # if not email:
        #     raise ValueError('Users must have an email')
        # if not username:
        #     raise ValueError('Users must have an username')

        # email = 'test-oka@aaa.com'
        # password = 'masahi0205'

        user = self.model(username=username,
                          email=email,
                          password=password
                          )
        user.is_active = True
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        """
        スーパーユーザ作成

        :param username: ユーザID
        :param email: メールアドレス
        :param password: パスワード
        :return: Userオブジェクト
        """
        user = self.create_user(username=username,
                                email=email,
                                password=password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


@python_2_unicode_compatible
class User(AbstractBaseUser, PermissionsMixin):
    """
    ユーザ情報を管理する
    """
    class Meta:
        verbose_name = 'ユーザ'
        verbose_name_plural = 'ユーザ'

    def get_short_name(self):
        """
        ユーザの苗字を取得する

        :return: 苗字
        """
        return self.last_name

    # def get_full_name(self):
    #     """
    #     ユーザのフルネームを取得する
    #
    #     :return: 苗字 + 名前
    #     """
    #     return self.last_name + self.first_name


    username = models.CharField(verbose_name='ユーザー名',
                                # unique=True,
                                max_length=30)
    # username = models.CharField(verbose_name='ユーザID',
    #                             unique=True,
    #                             max_length=30)
    # last_name = models.CharField(verbose_name='苗字',
    #                              max_length=30,
    #                              default=None)
    # first_name = models.CharField(verbose_name='名前',
    #                               max_length=30,
    #                               default=None)

    # password = models.CharField(verbose_name='パスワード',
    #                           null=True,
    #                           default=None,
    #                           max_length=128)


    email = models.EmailField(verbose_name='メールアドレス',
                            #   unique=True,
                              null=True,
                              default=None)

    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(verbose_name='有効フラグ',
                                    default=True)
    is_staff = models.BooleanField(verbose_name='管理サイトアクセス権限',
                                   default=False)

    # USERNAME_FIELD = 'username'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    objects = UserManager()

    def __str__(self):
        # return self.last_name + ' ' + self.first_name
        return self.username





















class Target(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vuforia_target_id = models.CharField(max_length=200, null=True)
    img_name = models.CharField(max_length=100, null=True)
    content_name = models.CharField(max_length=100, null=True)
    view_count = models.IntegerField(null=True)
    view_count_limit = models.IntegerField(null=True)
    view_state = models.PositiveSmallIntegerField(null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    # class Meta:
    #     abstract = True


######## validation
def validate_even(value):
    if value % 2 != 0:
        raise ValidationError(
            _('%(value)s is not an even number'),
            params={'value': value},
        )

def validate_my_email(value):
    try:
        # validate_email("foo.bar@baz.qux")
        validate_email(value)
    except ValidationError as e:
        print("oops! wrong email")
        # raise ValidationError(_('%(value)s is not an even number'),params={'value': value},)
        raise ValidationError(_('%(value)s is not an even number'),params={'value': value},)
    else:
        print("hooray! email is valid")


class JapaneseEmailValidator(EmailValidator):
    user_regex = re.compile(
        r"(^[-.!#$%&'*+/=?^_`{}|~0-9A-Z]+$"  # dot-atom (\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*を省略
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"$)',  # quoted-string
        re.IGNORECASE)
