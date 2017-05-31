from django.db import models

# Create your models here.

class User(models.Model):
    mail = models.EmailField(max_length=254)
    password = models.CharField(max_length=2000)
    name = models.CharField(max_length=200)
    image_file_name = models.CharField(max_length=200)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    # class Meta:
    #     abstract = True

class Target(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vuforia_target_id = models.CharField(max_length=200)
    content_name = models.CharField(max_length=100)
    view_count = models.IntegerField()
    view_count_limit = models.IntegerField()
    view_state = models.PositiveSmallIntegerField()
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    # class Meta:
    #     abstract = True
