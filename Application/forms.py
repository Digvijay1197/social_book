from django import forms 
from django.forms import ModelForm
from .models import UploadedFile
from django.core.validators import FileExtensionValidator

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

        # def clean_file_field(self):
        #     file = self.cleaned_data.get('file')
        
        #     if not file.name.lower().endswith(('.pdf')):
        #         raise forms.ValidationError("Invalid file type. Only .pdf file types are allowed.")
            
                   
        #     return file
    
        # def clean_image_field(self):
        #     book_cover = self.cleaned_data.get('book_cover')
        
        #     if book_cover:
        #         if not book_cover.name.lower().endswith(('.jpeg')):
        #             raise forms.ValidationError("Invalid image format. Only JPEG images are allowed.")
            
        #     return book_cover