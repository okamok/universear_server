# @register.assignment_tag
# def get_messages_list_for_user(request):
#
#     return 'bbbbbbb'

from django import template

register = template.Library()

@register.simple_tag
def get_user_auth(request):
    return request.user

@register.simple_tag
def get_user_is_authenticated(request):
    return request.user.is_authenticated()
