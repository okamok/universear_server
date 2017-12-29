from django.core.management.base import BaseCommand, CommandError
import hlar.views as views
from time import sleep
from hlar.models import User, Target
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'delete Vuforia Target'

    # def add_arguments(self, parser):
    #     parser.add_argument('vuforia_target_id', nargs='+', type=str)

    def handle(self, *args, **options):
        print("del temp target")
        #### 簡易登録で10分以上経過したものを取得
        date = datetime.now() - timedelta(minutes=10)
        targets_object = Target.objects.filter(user_id__isnull=True,created_date__lte=date, del_flg=0)

        print(targets_object)

        for target in targets_object:
            print(target)

            #### 削除処理
            ret = views.del_target_func(target)

            if (ret['ret'] == False):
                # @ToDo 失敗ログ出力
                print('err del')
            else:
                print('del comp')
