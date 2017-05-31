from django.forms import ModelForm
from hlar.models import Target


class TargetForm(ModelForm):
    """ターゲットのフォーム"""
    class Meta:
        model = Target
        fields = ('content_name', 'vuforia_target_id', 'view_count', )
