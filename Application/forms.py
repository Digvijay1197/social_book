from django import forms 
from django.forms import ModelForm
from .models import UploadedFile

# creating file upload form 
class UploadFileForm(ModelForm):
        class Meta:
           model = UploadedFile
           fields = ['user', 'title', 'description', 'cost', 'year_published', 'book_cover', 'file']

           widgets= {
                 'user' : forms.HiddenInput(),
           }