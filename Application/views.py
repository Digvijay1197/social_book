from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from rest_framework.decorators import action, api_view
from rest_framework.parsers import FormParser, MultiPartParser
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
from rest_framework.response import Response 
from .serializer import CustomUserSerializer, ProfileSerializer
from .forms import UploadFileForm
from django.core.mail import send_mail
import math, random

# Create your views here.
@csrf_protect
def login_run(request):
    if request.method=="POST":
         username=request.POST.get('username')
         password=request.POST.get('password')
         user = authenticate(request, username=username, password=password)
         if user is not None:
             OTP=generateOTP()
             print(OTP)
             request.session['OTP'] = OTP
             request.session.save()
             send_mail(
                'OTP for login:',
                f'your otp for login is :{OTP}',
                'digvijaysawant1310@gmil.com',
                [user.email],
                fail_silently=False,
            )
             login(request,user)
             return redirect('otpVerification')
         else:
             messages.error(request,'username or password not correct or empty')
            #  return HttpResponse("username or password is incorrect")
    return render(request,'Application/login.html')

def generateOTP() :
     digits = "0123456789"
     OTP = ""
     for i in range(4) :
         OTP += digits[math.floor(random.random() * 10)]
     return OTP


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
       

        print(publicVisibility)

        if publicVisibility == 'on':
            publicVisibility = True
        else:
             publicVisibility = False

        today =  timezone.now()
        age = today.year - int(birthYear)

        if pass1 != pass2:
            messages.error(request,'your password and confirm password should match')
        elif email=="" or username=="" or pass1=="" or pass2=="":
             messages.error(request,'please fill mandatory fields like email, uname, password, confirm password')
        else:
            newuser = CustomUser.objects.create_user(email,pass1, username, publicVisibility, address, birthYear, age)
            newuser.save()
           
            send_mail(
                'Registration Confirmation',
                'thank for registering on social book.',
                'digvijaysawant1310@gmil.com',
                [email],
                fail_silently=False,
            )
            #messages.success(request, 'Form submission successful')
            return redirect('login')
            
    return render(request,'Application/register.html')

def otpVerification_run(request):
    if request.method=="POST":
        otp = request.POST.get('OTP')
        print("otp:",otp)
        sessionOTP = request.session.get('OTP')
        print("session otp:",sessionOTP)
        if otp == sessionOTP:
            return redirect('index')
        else:
            messages.error(request,'entered otp is invalid !!!!')
    return render(request,'Application/otpVerification.html')

def index_run(request):
    return render(request,'Application/index.html')


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
        # if 'submitted' in request.GET:
        #     submitted = True
        return render(request,'Application/uploadFiles.html', {'form' : form})
    

def uploadedFiles_run(request):
    # try:
        if request.method == 'POST':
            allUser = request.POST.get('allUser')
            userId = request.POST.get('userId')
            currentUser = request.user
            if allUser == 'on':
                uploadedFilesList = UploadedFile.objects.all()
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList})
            elif UploadedFile.objects.filter(user_id=userId):
                uploadedFilesList = UploadedFile.objects.filter(user_id=userId)
                return render(request,'Application/uploadedFiles.html',{'allFiles':uploadedFilesList})
        else:
            uploadedFilesList = None
            return render(request,'Application/uploadedFiles.html', {'allFiles': uploadedFilesList})
  


class ListUsers(viewsets.ModelViewSet):
    """
    View to list all users in the system.

    * Requires token authentication.
    * Only admin users are able to access this view.
    """
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    # def get(self, request, format=None):
    #     """
    #     Return a list of all users.
    #     """
    #     usernames = [user.username for user in CustomUser.objects.all()]
    #     return Response(usernames)

    # below code helps to serialize entire list of customUser objects and send it
    serializer_class = CustomUserSerializer
    def get_queryset(self):
        return CustomUser.objects.all()
    
class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    # parser_classes = (FormParser, MultiPartParser)

    # @action(detail=True, methods=['put'])
    # def profile(self, request, pk=None):
    #     user = self.get_object()
    #     profile = user.profile
    #     serializer = ProfileSerializer(profile, data=request.data)
    #     if serializer.is_valid():
    #        serializer.save()
    #        return Response(serializer.data, status=200) 
    #     else:
    #        return Response(serializer.error, status=400)
        



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
    return redirect('login')