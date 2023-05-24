from django.shortcuts import redirect
from .models import UploadedFile
from django.contrib import messages

def has_uploaded_books(view_func):
    def wrapper(request, *args, **kwargs):
        user = request.user
        uploaded_books = UploadedFile.objects.filter(user=user)
        if uploaded_books:
            return view_func(request, *args, **kwargs)
        else:
            messages.error(request,'you have not uploaded any book yet !!')
            return redirect('uploadFiles')
    return wrapper