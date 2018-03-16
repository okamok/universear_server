# import sys

# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, EmailValidator
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse
from django.db import IntegrityError
from django.contrib import admin
import re

DEFAULT_PASS = 'A2v5BKe8'


class Oauth(models.Model):
    oauth_token = models.CharField(max_length=300, null=True)
    oauth_token_secret = models.CharField(max_length=300, null=True)
    access_token = models.CharField(max_length=300, null=True)
    access_token_secret = models.CharField(max_length=300, null=True)
    id_in_auth_app = models.CharField(max_length=80, null=True)
    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

##### user 作り直し
@python_2_unicode_compatible
class UserManager(BaseUserManager):

    def create_user(self, username, email, password=''):
        """
        ユーザ作成

        :param username: ユーザID
        :param email: メールアドレス
        :param password: パスワード
        :return: Userオブジェクト
        """
        if not email:
            raise ValueError('Users must have an email')

        # passwordが入力されていない場合はデフォルトを設定
        if not password:
            password = DEFAULT_PASS

        user = self.model(username=username,
                          email=email,
                          password=password
                          )
        user.is_active = True
        user.set_password(password)

        # validation
        try:
            user.save(using=self._db)
            print('UserManager -1-')
            return user
        except Exception as e:
            return None


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
        verbose_name_plural = 'ユーザ達'

    def get_short_name(self):
        """
        ユーザの苗字を取得する

        :return: 苗字
        """
        return self.username

    ######## DB カラム定義
    username = models.CharField(verbose_name='ユーザー名',
                                # unique=True,
                                max_length=30)

    email = models.EmailField(verbose_name='メールアドレス',
                              unique=True,
                              null=True,
                              default=None)

    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(verbose_name='有効フラグ',
                                    default=True)
    is_staff = models.BooleanField(verbose_name='管理サイトアクセス権限',
                                   default=False)


    ######## ユーザー認証時のIDとなるカラム
    USERNAME_FIELD = 'email'


    REQUIRED_FIELDS = ['username']
    objects = UserManager()

    def __str__(self):
        return self.username


# @python_2_unicode_compatible
class Target(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    vuforia_target_id = models.CharField(max_length=200, null=True)
    img_name = models.CharField(max_length=100, null=True)
    content_name = models.CharField(max_length=100, null=True)
    target_name = models.CharField(max_length=200, null=True)
    target_link_URL = models.CharField(max_length=300, null=True)
    view_count = models.IntegerField(null=True)
    view_count_limit = models.IntegerField(null=True)
    view_state = models.PositiveSmallIntegerField(null=True)
    del_flg = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)


class Payment(models.Model):
    # ユーザーID user_id
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # 決済日時 payment_date
    payment_date = models.DateTimeField(auto_now_add=True)

    # ターゲットID target_id
    target = models.ForeignKey(Target, on_delete=models.CASCADE)

    # 金額 amount
    amount = models.IntegerField(null=True)

    # 購入回数 brought_view_count
    brought_view_count = models.IntegerField(null=True)

    # トークンID token_id
    token_id = models.CharField(max_length=200, null=True)

    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)



class AccessLog(models.Model):

    # ターゲットID target_id
    target = models.ForeignKey(Target, on_delete=models.CASCADE)

    # アクセス日時 access_date
    access_date = models.DateTimeField(auto_now_add=True)

    # オペレーションシステム operating_system
    operating_system = models.CharField(max_length=300, null=True)

    # デバイスID device_unique_identifier
    device_unique_identifier = models.CharField(max_length=300, null=True)

    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
