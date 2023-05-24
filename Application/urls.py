from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
from .views import UserLoginView
from Application.views import ListUsers, CustomAuthToken, CustomUserViewSet
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('login', views.login_run, name='login'),
    path('otpVerification', views.otpVerification_run, name='otpVerification'),
    path('forgotPassword', views.forgotPassword_run, name='forgotPassword'),
    path('resendOtp', views.resendOtp, name='resendOtp'),
    path('logout', views.logout_run, name='logout'),
    path('register',views.register_run, name='register'),
    path('index/',views.index_run, name='index'),
    path('authorsAndSellers',views.authorsAndSellers_run, name='authorsAndSellers'),
    path('ownFiles',views.ownFiles_run, name='ownFiles'),
    path('uploadFiles',views.uploadFiles_run, name='uploadFiles'),
    path('uploadedFiles',views.uploadedFiles_run, name='uploadedFiles'),
    path('api/users/', ListUsers.as_view({'get':'list'})),
    path('api/users/<int:pk>', CustomUserViewSet.as_view({'get':'list'})),
    # path('api/token/auth/', CustomAuthToken.as_view()),
    path('api/token/',TokenObtainPairView.as_view(), name='get_token'),
    path('api/token/refresh',TokenRefreshView.as_view(),name= 'refresh_token'),
    path('api/token/verify',TokenVerifyView.as_view(), name='verify_token'),
     path('api/login/', UserLoginView.as_view(), name='user_login'),
]


##first two lines are written for below if condition.If is used for mapping url path of file upload.
# Also, see the configurations made in settings.py for it. i.e.  MEDIA_ROOT=os.path.join(BASE_DIR,"media")
# and MEDIA_URL="/media/"
if settings.DEBUG:
    urlpatterns+=static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)