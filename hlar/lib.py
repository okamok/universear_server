from hlar.models import User, Target
from pprint import pprint
from django.db.models import F

def get_targets_popular():

    #### DBからデータ取得
    targets_object = Target.objects.filter(del_flg=False,view_count__lt=F('view_count_limit')).order_by('-view_count')[:4]

    # querysetの中身みれる
    # pprint([vars(p) for p in targets_object])

    return targets_object
