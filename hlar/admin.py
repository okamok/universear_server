from django.contrib import admin
from hlar.models import User, Target, AccessLog
from django.conf.urls import url
from django.template.response import TemplateResponse

class UserAdmin(admin.ModelAdmin):
    # 一覧に表示したい項目を定義
    list_display = ("username", "email")

admin.site.register(User, UserAdmin)
admin.site.register(Target)
# Register your models here.


# adminに独自ページを追加
# @admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):

    list_display = ("id", "access_date", "operating_system")

    def get_urls(self):
        print("-----access------")
        urls = super(AccessLogAdmin, self).get_urls()
        my_urls = [
            url(r'^my_view/$', self.my_view),
        ]
        return my_urls + urls

    def my_view(self, request):
        # ...
        value = "test"

        context = dict(
           # Include common variables for rendering the admin template.
           self.admin_site.each_context(request),
           # Anything else you want in the context...
           key=value,
        )
        return TemplateResponse(request, "admin/hlar/accesslog/my_view.html", context)

admin.site.register(AccessLog, AccessLogAdmin)
