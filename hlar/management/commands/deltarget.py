from django.core.management.base import BaseCommand, CommandError
# from polls.models import Question as Poll
# from ...vuforiaAPI import del_target
# from hlar.views import del_target
# from hlar.vuforiaAPI import add_target, get_targets, get_targets_user_id, judge_vws_result, get_target_id_from_name, update_target, del_target, get_target_by_id, duplicates
import hlar.views as views
from time import sleep

class Command(BaseCommand):
    # help = 'Closes the specified poll for voting'
    help = 'delete Vuforia Target'

    def add_arguments(self, parser):
        # parser.add_argument('poll_id', nargs='+', type=int)
        parser.add_argument('vuforia_target_id', nargs='+', type=str)

    def handle(self, *args, **options):
        print("deltarget -0-")
        print(options['vuforia_target_id'][0])

        target_id = options['vuforia_target_id'][0]
        # target_id = options['vuforia_target_id'][0]
        # target_id = target_id.replace("[", "")
        # target_id = target_id.replace("]", "")
        # target_id = target_id.replace("'", "")
        #
        # print(target_id)


        comp = False
        err_cnt = 0
        while comp == False:
            if err_cnt > 60:
                break

            print("deltarget -0.5-")
            response_content = views.del_target(target_id)
            print('deltarget -1-:del_response')
            print(response_content)

            if views.judge_vws_result(response_content['result_code']):
                # 正常終了
                print('deltarget -2-')
                comp = True
                # return redirect('hlar:target_list')
            else:
                # エラー
                print('deltarget -3-')
                print(response_content['result_code'])
                err_cnt = err_cnt + 1
                sleep(10)   # 10秒停止

                # return render(request, 'hlar/target_edit.html', dict(msg=response_content['result_code']))

            #    a = a + 1

        print('deltarget -4-')


        # for poll_id in options['poll_id']:
        #     try:
        #         poll = Poll.objects.get(pk=poll_id)
        #     except Poll.DoesNotExist:
        #         raise CommandError('Poll "%s" does not exist' % poll_id)
        #
        #     poll.opened = False
        #     poll.save()
        #
        #     self.stdout.write(self.style.SUCCESS('Successfully closed poll "%s"' % poll_id))
