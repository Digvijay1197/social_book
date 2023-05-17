from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from .manager import CustomUserManager
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.core.validators import FileExtensionValidator

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)

class CustomUser(AbstractUser):
    username = models.CharField(max_length=20, null=True, blank=True, unique=True)
    email = models.EmailField(_("email address"), unique=True)
    publicVisibility = models.BooleanField(default=False)
    birthYear = models.PositiveIntegerField(null=True, blank=True)
    address = models.CharField(max_length=200,  null=True, blank=True)
    age = models.PositiveIntegerField(null=True, blank=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ['email']

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class UploadedFile(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    title = models.CharField(max_length=255)
    description = models.TextField(null=False)
    cost = models.DecimalField(max_digits=8, decimal_places=2, null=False)
    year_published = models.IntegerField(null=False)
    book_cover =  models.ImageField(upload_to='TestFile/cover', max_length=255, null=True, blank=True)
    file = models.FileField(upload_to='TestFiles/pdf', validators= [FileExtensionValidator(allowed_extensions=['pdf'])])

class Profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    designation = models.CharField(max_length=20, null=False, blank=False)
    salary = models.IntegerField(null=True, blank=True)
    picture = models.ImageField(upload_to='TestFile/profile', max_length=255, null=True, blank=True)

    class Meta:
        ordering = ('-salary',)

    def _str_(self):
        return  "{0} -{1}".format(self.user.username, self.designation)

