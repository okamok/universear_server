from django.core.management.base import BaseCommand, CommandError
import hlar.views as views
from time import sleep

class Command(BaseCommand):
    help = 'delete Vuforia Target'

    def add_arguments(self, parser):
        parser.add_argument('vuforia_target_id', nargs='+', type=str)

    def handle(self, *args, **options):

        target_id = options['vuforia_target_id'][0]

        comp = False
        err_cnt = 0
        while comp == False:
            if err_cnt > 60:
                break

            response_content = views.del_target(target_id)

            if views.judge_vws_result(response_content['result_code']):
                # 正常終了
                comp = True
            else:
                # エラー
                print(response_content['result_code'])
                err_cnt = err_cnt + 1
                sleep(10)   # 10秒停止
