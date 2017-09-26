"""composeexample URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Import the include() function: from django.conf.urls import url, include
    3. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url, patterns
from django.contrib import admin
from django.conf import settings

from hlar.urls import router as hlar_router
from django.contrib.auth import views as auth_views
from hlar import views
from hlar.forms import LoginForm

from hlar.views import UserProfileRegistration

# from registration.views import RegistrationView
from registration.backends.default.views import RegistrationView
from hlar.forms import CustomRegistrationForm

from django.http import HttpResponseRedirect

urlpatterns = [
    url(r'^admin/', admin.site.urls),

    url(r'^hlar/', include('hlar.urls'), name='hlar_index'),

    url(r'^api/', include(hlar_router.urls)),

    url(r'^login/$', auth_views.login, {'template_name': 'hlar/login.html', 'authentication_form': LoginForm}),

    url('', include('social.apps.django_app.urls', namespace='social')),    # oauth用
    # url('', include('django.contrib.auth.urls', namespace='auth')),

    url(r'^logout/$', auth_views.logout, {'template_name': 'hlar/logged_out.html'}),
    url(r'^signup/$', views.signup, name='signup'),


    # url(r'^accounts/register/$', UserProfileRegistration.as_view(), name='registration_register'),

    # サインアップ
    url(r'^accounts/register/$', RegistrationView.as_view(form_class=CustomRegistrationForm), name='registration_register',),
    url(r'^accounts/', include('registration.backends.default.urls')),

    # パスワードリセット
    url(r'^reset/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', 'django.contrib.auth.views.password_reset_confirm', name='password_reset_confirm'),
    url(r'^password/reset/complete/$', auth_views.password_reset_complete, name='password_reset_complete'),

    # パスワード変更
    url(r'^password/change/$', auth_views.password_change, name='password_change'),
    url(r'^password/change/done/$', auth_views.password_change_done, name='password_change_done'),

    # url(r'^password/change/$',
    #     auth_views.PasswordChangeView.as_view(
    #         success_url=reverse_lazy('auth_password_change_done')),
    #     name='auth_password_change'),

    # url(r'^password/change/done/$',
    #     auth_views.PasswordChangeDoneView.as_view(),
    #     name='auth_password_change_done'),

    # url('/', views.hlar_top, name='hlar_top'),
    url(r'^$', lambda r: HttpResponseRedirect('hlar/')),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += patterns('',
        url(r'^__debug__/', include(debug_toolbar.urls)),
    )
