from django.contrib import admin
from hlar.models import User,Target

class UserAdmin(admin.ModelAdmin):
    list_display = ("username", "email")

admin.site.register(User, UserAdmin)
admin.site.register(Target)
# Register your models here.
