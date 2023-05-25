from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import auth
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from rest_framework.decorators import action, api_view,permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from .models import CustomUser
from django.utils import timezone
from .forms import UploadFileForm
from .models import UploadedFile
from django.shortcuts import render
from rest_framework.authtoken.views import ObtainAuthToken 
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response 
from .serializer import CustomUserSerializer, ProfileSerializer
from .forms import UploadFileForm
from django.core.mail import send_mail
import math, random
from django.contrib.auth.decorators import login_required
from django_otp.oath import TOTP
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.db.models import Q
from datetime import datetime, timedelta
from django.utils import timezone
from .decorators import has_uploaded_books
from sqlalchemy import create_engine, text
import sqlalchemy
import pandas as pd

# Create your views here.
@csrf_protect
def login_run(request):
    if request.method=="POST":
         username=request.POST.get('username')
         password=request.POST.get('password')
         user = authenticate(request, username=username, password=password)
         if user is not None:
            OTP=generateOTP()
            request.session['OTP'] = OTP
            request.session['username'] = username
            request.session['password'] = password
            request.session.save()
            send_mail(
                'OTP for login:',
                f'your otp for login is :{OTP}',
                'digvijaysawant1310@gmil.com',
                [user.email],
                fail_silently=False,
            )
            # login(request,user)
            return redirect('otpVerification')
         else:
            messages.error(request,'username or password not correct or empty')
            return redirect('login')
            #  return HttpResponse("username or password is incorrect")
    return render(request,'Application/login.html')


def generateOTP() :
     digits = "0123456789"
     OTP = ""
     for i in range(4) :
         OTP += digits[math.floor(random.random() * 10)]
     return OTP

def resendOtp(request) :
    digits = "0123456789"
    OTP = ""
    for i in range(4) :
        OTP += digits[math.floor(random.random() * 10)]
     
    request.session['OTP'] = OTP
    username = request.session.get('username')
    password = request.session.get('password')
    user = authenticate(request, username=username, password=password)
    request.session.save()
    send_mail(
                'OTP for login:',
                f'your otp for login is :{OTP}',
                'digvijaysawant1310@gmil.com',
                [user.email],
                fail_silently=False,
            )
    return redirect('otpVerification')

class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        return Response({'refresh': str(refresh), 'access': str(refresh.access_token)})


@csrf_protect
def register_run(request):
    if request.method=='POST':
        email=request.POST.get('email')
        username=request.POST.get('username')
        pass1=request.POST.get('password')
        pass2=request.POST.get('confirmPassword')
        publicVisibility = request.POST.get("publicVisibility")
        address = request.POST.get("address")
        birthYear = request.POST.get("birthYear")
        token=None
        expiryTime=None
        print(birthYear)
       

        print(publicVisibility)

        if publicVisibility == 'on':
            publicVisibility = True
        else:
             publicVisibility = False

        today =  timezone.now()
       
        if username:
            age = today.year - int(birthYear)
            newuser = CustomUser.objects.create_user(email,pass1, username, publicVisibility, address, birthYear, age, token, expiryTime)
            newuser.save()
           
            send_mail(
                'Registration Confirmation',
                'thank for registering on social book.',
                'digvijaysawant1310@gmil.com',
                [email],
                fail_silently=False,
            )
            messages.success(request, 'Form submission successful')
            return redirect('login')
        else:
            return redirect('register')
            
    return render(request,'Application/register.html')


# @api_view(['GET'])
@permission_classes([AllowAny])
def otpVerification_run(request):
    
    if request.method=="POST":
        otp = request.POST.get('OTP')
        print("otp:",otp)
        sessionOTP = request.session.get('OTP')
        print("session otp:",sessionOTP)
        # cUser = CustomUser.objects.get(id=request.user.id)
        if otp == sessionOTP:
            username = request.session.get('username')
            password = request.session.get('password')
            user = authenticate(request, username=username, password=password)
            login(request,user)

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            request.session['access_token'] = access_token
            request.session.save()
            print("access_token:",access_token)

            user.token = access_token

            current_time = datetime.now()
            new_time = current_time + timedelta(hours=1)
            user.expiryTime = new_time
            user.save()
             
            # index_url = 'http://127.0.0.1:8000/index?token='+access_token
            # return redirect(index_url)
            return redirect('index')
        else:
            messages.error(request,'entered otp is invalid !!!! resend otp and try again !!')
            request.session['OTP'] = None
        # user = request.session.get('user')
        
    return render(request,'Application/otpVerification.html')

# def otpVerification_run(request):
    
#     if request.method=="POST":
#         otp = request.POST.get('OTP')
#         print("otp:",otp)
#         sessionOTP = request.session.get('OTP')
#         print("session otp:",sessionOTP)
        
#         if otp == sessionOTP:
#             username = request.session.get('username')
#             password = request.session.get('password')
#             user = authenticate(request, username=username, password=password)
#             login(request,user)
#             return redirect('index')
#         else:
#             messages.error(request,'entered otp is invalid !!!!')
#         # user = request.session.get('user')
        
#     return render(request,'Application/otpVerification.html')


@login_required(login_url='login')
def index_run(request):
    user = request.session.get('user')
    # access_token = request.GET.get('token', None)
    return render(request,'Application/index.html',  {'User': user})

# @login_required(login_url='login')
def forgotPassword_run(request):
    user = request.session.get('user')
    return render(request,'Application/forgot-password.html',  {'User': user})


@login_required(login_url='login')
def authorsAndSellers_run(request):
    
    # access_token = request.GET.get('token', None)
    if request.method == 'POST':
        publicVisibility = request.POST.get('publicVisibility')
        
        userStatus = request.POST.get('user_status')
        if publicVisibility == 'on':
            # filteredCustomers = CustomUser.objects.filter(publicVisibility=1)
            engine = create_engine('postgresql://postgres:Digvijay%401197@localhost:5432/social_book')
            conn= engine.connect()
            query = text('SELECT * from public."Application_customuser" where "publicVisibility"= :value')
            params = {'value': 'true'}
            result = conn.execute(query, params)
            filteredCustomers = [row for row in result]
            print(filteredCustomers)
            conn.close()

        elif userStatus == '1':
            filteredCustomers = CustomUser.objects.filter(is_active=1)
        elif userStatus == '0':
            filteredCustomers = CustomUser.objects.filter(is_active=0)
        elif userStatus == '2':
            filteredCustomers = CustomUser.objects.all()
    else:
        filteredCustomers = None

    return render(request,'Application/authorsAndSellers.html', {'CustomUsers': filteredCustomers})


@login_required(login_url='login')
def uploadFiles_run(request):
    # submitted = False 
    # access_token = request.GET.get('token', None)
    user_id = request.user.id
    initial_data = {
        'user': user_id,
    }

    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            print("form is valid")
            form.save()
            messages.success(request, 'book uploaded successfully')
            return redirect('ownFiles')
        else:
            print(form.errors)
            # Check for specific file and image field errors
            if 'file' in form.errors:
                messages.error(request, 'Error with file field: ' + ', '.join(form.errors['file']))
                return redirect('uploadFiles')
            if 'book_cover' in form.errors:
                messages.error(request, 'Error with image field: ' + ', '.join(form.errors['book_cover']))
                return redirect('uploadFiles')
    
            # messages.error(request, 'image should be jpeg type and file of pdf format.')
            
    else:
        form = UploadFileForm(initial = initial_data)
       
        return render(request,'Application/uploadFiles.html', {'form' : form})



@login_required(login_url='login')
# @has_uploaded_books
def ownFiles_run(request):

        currentUserId = request.user.id
        print(currentUserId)
        currentUserList =  UploadedFile.objects.filter(user_id=currentUserId)
        
        if request.method == 'GET':
                if currentUserList:
                    return render(request,'Application/ownFiles.html',{'currentUserFiles':currentUserList})
                else:
                    messages.error(request,'you have not uploaded any book')
                    return redirect('uploadFiles')


        else:
            currentUserList = None
            return render(request,'Application/ownFiles.html', {'currentUserFiles':currentUserList})
  

@login_required(login_url='login')
def uploadedFiles_run(request):
    # try:
        # access_token = request.GET.get('token', None)
        currentUserId = request.user.id
        print(currentUserId)
        currentUserList =  UploadedFile.objects.filter(user_id=currentUserId)
        
        if request.method == 'GET':
            return render(request,'Application/uploadedFiles.html',{'currentUserFiles':currentUserList})

        elif request.method == 'POST':
            allUser = request.POST.get('allUser')
            userId = request.POST.get('userId')
            title = request.POST.get('title')
            year = request.POST.get('year')
            print(f'year:{year}')
            print(f'allUser:{allUser}')
            print(f'userId:{userId}')
            print(f'title:{title}')
            print(f'currentID:{currentUserId}')
            if allUser == 'on':
                uploadedFilesList = UploadedFile.objects.all()
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and len(userId)>0 and len(title)>0 and len(year)>0:
                # The from django.db.models import Q statement in Django allows you to use the Q object to perform 
                # complex database queries with logical operators like OR and AND.
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(year_published=int(year)), Q(title=title))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and year == "" and userId != "" and len(title)>0:
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(title=title))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})

            if allUser is None and len(title)==0 and userId != "" and year != "":
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(year_published=int(year)))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId == "" and  len(title)>0 and year != "":
                uploadedFilesList = UploadedFile.objects.filter(Q(title=title), Q(year_published=int(year)))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId == "" and len(title)>0 and year == "":
                uploadedFilesList = UploadedFile.objects.filter(title=title)
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId != "" and len(title)==0 and year == "":
                uploadedFilesList = UploadedFile.objects.filter(user_id=int(userId))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            if allUser is None and userId == "" and len(title)==0 and year != "":
                uploadedFilesList = UploadedFile.objects.filter(year_published=int(year))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            else:
                uploadedFilesList = None
                return render(request,'Application/uploadedFiles.html', {'allFiles': uploadedFilesList,'currentUserFiles':currentUserList})
        else:
            uploadedFilesList = None
            return render(request,'Application/uploadedFiles.html', {'allFiles': uploadedFilesList,'currentUserFiles':currentUserList})
  


class ListUsers(viewsets.ModelViewSet):
    """
    View to list all users in the system.

    * Requires token authentication.
    * Only admin users are able to access this view.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializer
    def get_queryset(self):
        return CustomUser.objects.all()
    

class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })
    
def logout_run(request):
    auth.logout(request)
    return redirect('login')

