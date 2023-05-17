from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
from Application.views import ListUsers, CustomAuthToken, CustomUserViewSet

urlpatterns = [
    path('login', views.login_run, name='login'),
     path('otpVerification', views.otpVerification_run, name='otpVerification'),
    path('logout', views.logout_run, name='logout'),
    path('register',views.register_run, name='register'),
    path('index',views.index_run, name='index'),
    path('authorsAndSellers',views.authorsAndSellers_run, name='authorsAndSellers'),
    path('uploadFiles',views.uploadFiles_run, name='uploadFiles'),
    path('uploadedFiles',views.uploadedFiles_run, name='uploadedFiles'),
    path('api/users/', ListUsers.as_view({'get':'list'})),
    path('api/users/<int:pk>', CustomUserViewSet.as_view({'get':'list'})),
    path('api/token/auth/', CustomAuthToken.as_view()),
]


##first two lines are written for below if condition.If is used for mapping url path of file upload.
# Also, see the configurations made in settings.py for it. i.e.  MEDIA_ROOT=os.path.join(BASE_DIR,"media")
# and MEDIA_URL="/media/"
if settings.DEBUG:
    urlpatterns+=static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)