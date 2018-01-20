from hlar.models import User, Target
from pprint import pprint
from django.db.models import F

def get_targets_popular():

    #### pythonのDBからデータ取得
    # targets_object = Target.objects.all().order_by('-view_count')[:4]
    targets_object = Target.objects.filter(del_flg=False,view_count__lt=F('view_count_limit')).order_by('-view_count')[:4]
    # user_obj = User.objects.filter(email=form.cleaned_data.get('email'))[0]

    print('targets_object_aaa')

    # querysetの中身みれる
    pprint([vars(p) for p in targets_object])

    return targets_object
