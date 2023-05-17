from Application.views import CustomUserViewSet
from rest_framework import routers

router = routers.DefaultRouter()
router.register('customUser',CustomUserViewSet)
