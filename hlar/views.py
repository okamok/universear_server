import json
import base64

from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.template import loader
from django.views import generic
from django.utils import timezone

from hlar.models import User, Target
from hlar.forms import TargetForm
from hlar.vuforiaAPI import add_target, get_targets, get_targets_user_id, judge_vws_result, get_target_id_from_name

SERVER_ACCESS_KEYS = '6968bbd6779ed68181552a8449c786bf85bfe650'
SERVER_SECRET_KEYS = '5a244dbd3afd62b6808b65a55b3a9a63187e543b'
# TARGET_FILE_PATH = './tmp/'
TARGET_FILE_PATH = './static/images/'

def target_list(request):
#    return HttpResponse('ターゲットの一覧')
    # targets = Target.objects.all().order_by('id')

    # @ToDo user_idを動的に入れる
    targets = get_targets_user_id(1)


    return render(request,
                  'hlar/target_list.html',     # 使用するテンプレート
                  {'targets': targets})         # テンプレートに渡すデータ

def target_edit(request, target_id=None):
    # return HttpResponse('ターゲットの編集')

    if target_id:   # target_id が指定されている (修正時)
        target = get_object_or_404(Target, pk=target_id)
    else:         # target_id が指定されていない (追加時)
        target = Target()

    if request.method == 'POST':
        # POST 時

        ######## ターゲットファイル
        filePath = TARGET_FILE_PATH + request.POST['target_file_name']

        # file読み込み
        with open(filePath, 'rb') as f:
            contents = f.read()

        # base64でencode
        encTargetFileBase64 = base64.b64encode(contents)
        encTargetFile = encTargetFileBase64.decode('utf-8')


        ######## meta テキスト
        #### テキスト作成
        meta_file_name = request.POST['target_file_name'].replace('.','') + '.txt'
        metaPath = TARGET_FILE_PATH + meta_file_name

        metaContent = "{\n" \
                        '\t"title": "DEATHRO -CRAZY FOR YOU- music video",\n' \
                        '\t"url" : "http://zine.hiliberate.biz/movie/deathro_crazy_for_you.mp4"\n' \
                       '}'

        # ファイルが存在していれば削除
        if default_storage.exists(metaPath):
            default_storage.delete(metaPath)

        # ファイル保存
        default_storage.save(metaPath, ContentFile(metaContent))

        # file読み込み
        with open(metaPath, 'rb') as f:
            contents = f.read()

        # base64でencode
        encMetaFileBase64 = base64.b64encode(contents)
        encMetaFile = encMetaFileBase64.decode('utf-8')


        ######## ターゲット名
        target_name = request.POST['target_name']


        ######## Vuforia API で登録
        response_content = add_target(max_num_results='',
                                 include_target_data=encMetaFile,
                                 image=encTargetFile,
                                 target_name=target_name)

        print('4444')
        print(response_content)

        # if response_content['result_code'] == 'TargetNameExist'
        #
        # else :

        # if status == 200:
        #     print(query_response)
        #     # sys.exit(0)
        # else:
        #     print(status)
        #     print(query_response)
        #     # sys.exit(status)

        if judge_vws_result(response_content['result_code']):
            ######## DBに登録
            target.content_name = request.POST['target_file_name']
            target.user_id = 1 #@ToDo 決め打ち
            target.vuforia_target_id = response_content['target_id']

            # target = form.save(commit=False)

            target.save()

            return render(request, 'hlar/target_edit.html', dict(msg='登録が完了しました。'))
        else:
            return render(request, 'hlar/target_edit.html', dict(msg=response_content['result_code']))



        # form = TargetForm(request.POST, instance=target)  # POST された request データからフォームを作成
        # if form.is_valid():    # フォームのバリデーション
        #     target = form.save(commit=False)
        #     target.save()
        #     return redirect('hlar:target_list')
    else:
        # GET 時
        form = TargetForm(instance=target)  # target インスタンスからフォームを作成

#    c = Context({"my_name": "Adrian"})

    return render(request, 'hlar/target_edit.html', dict(form=form, target_id=target_id))

def target_del(request, target_id):
    return HttpResponse('ターゲットの削除')

def target_upload(request):
    targetFile = request.FILES['target']

    # 保存パス(ファイル名含む)
    filePath = TARGET_FILE_PATH + targetFile.name

    print("filePath")
    print(filePath)

    # ファイルが存在していれば削除
    if default_storage.exists(filePath):
        default_storage.delete(filePath)

    # ファイルを保存
    path = default_storage.save(filePath, ContentFile(targetFile.read()))

    print("path")
    print(path)

    dictData = {'filename':targetFile.name, "filelength":82}
    return HttpResponse(json.dumps(dictData))


## ListViewを使う方法
# class IndexView(generic.ListView):
#     template_name = 'hlar/index.html'   # これは hlar/templates/hlar/index.html
#     context_object_name = 'latest_target_list'    #これをやらないと'question_list'というデフォルトの名前でtemplateに渡される。
#
#     def get_queryset(self):
#
#         """
#         Return the last five published questions (not including those set to be
#         published in the future).
#         """
#         return Target.objects.all()







# def index(request):
#     return HttpResponse("Hello, world. You're at the polls index.")
