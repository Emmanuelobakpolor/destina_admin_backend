# users/serializers.py
from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'role')

    def create(self, validated_data):
        password = validated_data.pop('password')
        return User.objects.create_user(password=password, **validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        data['user'] = user
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'role')

class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'email', 'role', 'name', 'phone_number', 'location',
            'driver_license_front', 'driver_license_back', 'national_id', 'driver_photo',
            'monday_opening_time', 'monday_closing_time',
            'tuesday_opening_time', 'tuesday_closing_time',
            'wednesday_opening_time', 'wednesday_closing_time',
            'thursday_opening_time', 'thursday_closing_time',
            'friday_opening_time', 'friday_closing_time',
            'saturday_opening_time', 'saturday_closing_time',
            'sunday_opening_time', 'sunday_closing_time',
            'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'created_at', 'updated_at')

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        validated_data['role'] = 'driver'
        user = super().create(validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user
