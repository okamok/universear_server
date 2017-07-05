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

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^hlar/', include('hlar.urls')),
    url(r'^api/', include(hlar_router.urls)),

    url(r'^login/$', auth_views.login, {'template_name': 'hlar/login.html'}),

    url('', include('social.apps.django_app.urls', namespace='social')),    # oauth用
    # url('', include('django.contrib.auth.urls', namespace='auth')),

    url(r'^logout/$', auth_views.logout, {'template_name': 'hlar/logged_out.html'}),
    url(r'^signup/$', views.signup, name='signup'),


    # url('', include('django.contrib.auth.urls', namespace='auth')),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += patterns('',
        url(r'^__debug__/', include(debug_toolbar.urls)),
    )
