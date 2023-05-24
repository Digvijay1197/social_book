from django import forms 
from django.forms import ModelForm
from .models import UploadedFile

# creating file upload form 
class UploadFileForm(ModelForm):
        CHOICES = [
        (2023, '2023'),
        (2022, '2022'),
        (2021, '2021'),
        (2020, '2020'),
        (2019, '2019'),
        (2000, 'other'),
    ]

        year_published = forms.ChoiceField(choices=CHOICES, widget=forms.Select)
        class Meta:
           model = UploadedFile
           fields = ['user', 'title', 'description', 'cost', 'year_published', 'book_cover', 'file']

           widgets= {
                 'user' : forms.HiddenInput(),
           }