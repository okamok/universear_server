from django.conf.urls import url
from . import views
from django.conf import settings
from django.conf.urls import url, include

from rest_framework import routers
from hlar.views import UserViewSet, TargetViewSet

# 複数appがある場合、この設定を入れることでルーティング出来る
app_name = 'hlar'

urlpatterns = [
    url(r'^$', views.hlar_top, name='hlar_top'),   # TOP画面
    url(r'^index$', views.hlar_top, name='hlar_top'),   # TOP画面

    # target
    url(r'^target/$', views.target_list, name='target_list'),   # 一覧
    url(r'^target/add/$', views.target_edit, name='target_add'),  # 登録
    url(r'^target/temp_add/$', views.target_temp_edit, name='target_temp_add'),  # 登録
    url(r'^target/upload/$', views.target_upload, name='target_upload'),  # 登録
    url(r'^target/mod/(?P<target_id>\d+)/$', views.target_edit, name='target_mod'),  # 修正
    url(r'^target/del/(?P<target_id>\d+)/$', views.target_del, name='target_del'),   # 削除

    # user
    url(r'^user/add/$', views.user_add, name='user_add'),
    url(r'^user/edit/(?P<user_id>\d+)/$', views.user_edit, name='user_edit'),

    # url(r'^login/twitter/$', views.twitter_login, name='twitter_login'),   # twitter ログイン

    url(r'^user/manage/$', views.hlar_user_manage, name='hlar_user_manage'),   # oauth callback

    # 多言語対応
    url(r'^i18n/', include('django.conf.urls.i18n'), name='set_language'),

    # 決済用
    url(r'^target/payment/$', views.target_payment, name='target_payment'),  # 登録

    # β版モニター
    url(r'^beta_monitor/$', views.beta_monitor, name='beta_monitor'), 


    # url(r'^$', views.index, name='index'),
    #url(r'^$', views.IndexView.as_view(), name='index'),    # ListViewを使う場合
    # url(r'^(?P<pk>[0-9]+)/$', views.DetailView.as_view(), name='detail'),
    # url(r'^(?P<pk>[0-9]+)/results/$', views.ResultsView.as_view(), name='results'),
    # url(r'^(?P<question_id>[0-9]+)/vote/$', views.vote, name='vote'),
]


#api
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'targets', TargetViewSet)
