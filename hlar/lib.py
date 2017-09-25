from hlar.models import User, Target
from pprint import pprint

def get_targets_popular():

    #### pythonのDBからデータ取得
    targets_object = Target.objects.all().order_by('-view_count')[:4]
    print('targets_object_aaa')

    # querysetの中身みれる
    pprint([vars(p) for p in targets_object])

    return targets_object
