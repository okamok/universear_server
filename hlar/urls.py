from django.conf.urls import url

from . import views

from django.conf import settings

from rest_framework import routers
from hlar.views import UserViewSet, TargetViewSet

# 複数appがある場合、この設定を入れることでルーティング出来る
app_name = 'hlar'

urlpatterns = [
    # 書籍
    url(r'^target/$', views.target_list, name='target_list'),   # 一覧
    url(r'^target/add/$', views.target_edit, name='target_add'),  # 登録
    url(r'^target/upload/$', views.target_upload, name='target_upload'),  # 登録
    url(r'^target/mod/(?P<target_id>\d+)/$', views.target_edit, name='target_mod'),  # 修正
    url(r'^target/del/(?P<target_id>\d+)/$', views.target_del, name='target_del'),   # 削除



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
