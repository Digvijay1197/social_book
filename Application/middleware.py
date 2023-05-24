from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
import jwt
from django.conf import settings
from django.http import JsonResponse
from .models import CustomUser
import datetime
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth.models import auth

class TokenAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the request has a JWT token
        
        exempt_paths = ['/login','/otpVerification', '/logout', '/resendOtp', '/register']  # Add any other exempt paths if needed
        
        if request.path in exempt_paths:
            return self.get_response(request)

        # access_token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        
        # access_token = request.GET.get('token')
        access_token = request.session.get('access_token')
        # Verify and decode the JWT token
        try:
            decoded_token = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.exceptions.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # Check if the user exists
        try:
            print(decoded_token)
            
            user = request.user
            print(user.expiryTime.strftime("%H:%M:%S"))
            print(datetime.datetime.now().strftime("%H:%M:%S"))
            if user.expiryTime.strftime("%H:%M:%S") < datetime.datetime.now().strftime("%H:%M:%S"):
                print('inside if')
                messages.error(request,'session expired login again!!!!')
                user.token = ""
                user.expiryTime = None
                user.save()
                del request.session['access_token']
                print(request.session.get('access_token'))

                auth.logout(request)
                return redirect('login')

        except :
            # print('1')
            return JsonResponse({'error': 'User not found'}, status=401)

        # Attach the user object to the request
        request.user = user

        return self.get_response(request)
