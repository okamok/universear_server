# coding: utf-8

from rest_framework import serializers

from .models import User, Target, AccessLog


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name', 'mail')

class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = ('vuforia_target_id', 'view_count_limit', 'view_count', 'content_name')

    def update(self, instance, validated_data):
            """
            Update and return an existing `Snippet` instance, given the validated data.
            """
            instance.view_count_limit = 200
            # instance.code = validated_data.get('code', instance.code)
            # instance.linenos = validated_data.get('linenos', instance.linenos)
            # instance.language = validated_data.get('language', instance.language)
            # instance.style = validated_data.get('style', instance.style)
            instance.save()
            return instance


# class EntrySerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Entry
#         fields = ('title', 'body', 'created_at', 'status', 'author')

class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = ('target', 'access_date', 'operating_system', 'device_unique_identifier')
