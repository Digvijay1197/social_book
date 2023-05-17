from django.contrib.auth.models import User 
from .models import CustomUser, Profile
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['salary','designation','picture']

class CustomUserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'profile', 'first_name', 'last_name', 'email', 'is_staff', 'is_active', 'date_joined', 'is_superuser','publicVisibility','birthYear','address','age']
