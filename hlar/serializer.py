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
            instance.save()
            return instance


class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = ('target', 'access_date', 'operating_system', 'device_unique_identifier')
