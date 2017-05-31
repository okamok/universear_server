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

def target_list(request):
#    return HttpResponse('ターゲットの一覧')
    targets = Target.objects.all().order_by('id')
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

        print('deeeee')
        # print(request.POST['target_file_name'])
        filePath = './tmp/' + request.POST['target_file_name']
        print(filePath)

        # file読み込み
        with open(filePath, 'rb') as f:
            contents = f.read()

        # base64でencode
        enc_file = base64.b64encode(contents)

        # print(enc_file)

        return render(request, 'hlar/target_edit.html')

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
    filePath = './tmp/' + targetFile.name

    # ファイルが存在していれば削除
    if default_storage.exists(filePath):
        default_storage.delete(filePath)

    # ファイルを保存
    path = default_storage.save(filePath, ContentFile(targetFile.read()))


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
