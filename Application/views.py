from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import auth
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from rest_framework.decorators import action, api_view
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


# class UserLoginView(APIView):
#     def post(self, request):
#             username = request.data.get('username')
#             password = request.data.get('password')

#             user = authenticate(request, username=username, password=password)
#             if user is not None:
#                 refresh = RefreshToken.for_user(user)
#                 request.session['access_token'] = str(refresh.access_token)
            
#                 login(request,user)
#                 return redirect('otpVerification')
#             else:
#                 messages.error(request,'username or password not correct or empty')
                
#             return render(request,'Application/login.html')


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
        print(birthYear)
       

        print(publicVisibility)

        if publicVisibility == 'on':
            publicVisibility = True
        else:
             publicVisibility = False

        today =  timezone.now()
       

        # if pass1 != pass2:
        #     messages.error(request,'your password and confirm password should match')
        # elif email=="" or username=="" or pass1=="" or pass2=="":
        #     messages.error(request,'please fill mandatory fields like email, uname, password, confirm password')
        # else:
        if username:
            age = today.year - int(birthYear)
            newuser = CustomUser.objects.create_user(email,pass1, username, publicVisibility, address, birthYear, age)
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


# @login_required(login_url='login')
def otpVerification_run(request):
    
    if request.method=="POST":
        otp = request.POST.get('OTP')
        print("otp:",otp)
        sessionOTP = request.session.get('OTP')
        print("session otp:",sessionOTP)
        
        if otp == sessionOTP:
            username = request.session.get('username')
            password = request.session.get('password')
            user = authenticate(request, username=username, password=password)
            login(request,user)
            return redirect('index')
        else:
            messages.error(request,'entered otp is invalid !!!!')
        # user = request.session.get('user')
        
    return render(request,'Application/otpVerification.html')


@login_required(login_url='login')
def index_run(request):
    user = request.session.get('user')
    return render(request,'Application/index.html',  {'User': user})


@login_required(login_url='login')
def authorsAndSellers_run(request):
  
    if request.method == 'POST':
        publicVisibility = request.POST.get('publicVisibility')
        
        userStatus = request.POST.get('user_status')
        if publicVisibility == 'on':
            filteredCustomers = CustomUser.objects.filter(publicVisibility=1) 
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
    user_id = request.user.id
    initial_data = {
        'user': user_id,
    }

    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            print("form is valid")
            form.save()
            return redirect('uploadedFiles')
        else:
            print(form.errors)
            return redirect('index')
    else:
        form = UploadFileForm(initial = initial_data)
       
        return render(request,'Application/uploadFiles.html', {'form' : form})


@login_required(login_url='login')
def uploadedFiles_run(request):
    # try:
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
                print('1')
                uploadedFilesList = UploadedFile.objects.all()
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and len(userId)>0 and len(title)>0 and len(year)>0:
                print('2')
                # The from django.db.models import Q statement in Django allows you to use the Q object to perform 
                # complex database queries with logical operators like OR and AND.
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(year_published=int(year)), Q(title=title))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and year == "" and userId != "" and len(title)>0:
                print('3')
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(title=title))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})

            if allUser is None and len(title)==0 and userId != "" and year != "":
                print('4')
                uploadedFilesList = UploadedFile.objects.filter(Q(user_id=int(userId)), Q(year_published=int(year)))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId == "" and  len(title)>0 and year != "":
                print('5')
                uploadedFilesList = UploadedFile.objects.filter(Q(title=title), Q(year_published=int(year)))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId == "" and len(title)>0 and year == "":
                print('6')
                uploadedFilesList = UploadedFile.objects.filter(title=title)
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            
            if allUser is None and userId != "" and len(title)==0 and year == "":
                print('7')
                uploadedFilesList = UploadedFile.objects.filter(user_id=int(userId))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            if allUser is None and userId == "" and len(title)==0 and year != "":
                print('8')
                uploadedFilesList = UploadedFile.objects.filter(year_published=int(year))
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList, 'currentUserFiles':currentUserList})
            else:
                uploadedFilesList = None
                print("here")
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

