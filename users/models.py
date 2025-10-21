from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

ROLE_CHOICES = (
    ('admin', 'Admin'),
    ('user', 'User'),
    ('driver', 'Driver'),
)

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role='user', **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, role='admin', **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # required for admin site

    # Driver-specific fields
    name = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    driver_license_front = models.ImageField(upload_to='licenses/', blank=True, null=True)
    driver_license_back = models.ImageField(upload_to='licenses/', blank=True, null=True)
    national_id = models.ImageField(upload_to='national_ids/', blank=True, null=True)
    driver_photo = models.ImageField(upload_to='driver_photos/', blank=True, null=True)
    monday_opening_time = models.TimeField(blank=True, null=True)
    monday_closing_time = models.TimeField(blank=True, null=True)
    tuesday_opening_time = models.TimeField(blank=True, null=True)
    tuesday_closing_time = models.TimeField(blank=True, null=True)
    wednesday_opening_time = models.TimeField(blank=True, null=True)
    wednesday_closing_time = models.TimeField(blank=True, null=True)
    thursday_opening_time = models.TimeField(blank=True, null=True)
    thursday_closing_time = models.TimeField(blank=True, null=True)
    friday_opening_time = models.TimeField(blank=True, null=True)
    friday_closing_time = models.TimeField(blank=True, null=True)
    saturday_opening_time = models.TimeField(blank=True, null=True)
    saturday_closing_time = models.TimeField(blank=True, null=True)
    sunday_opening_time = models.TimeField(blank=True, null=True)
    sunday_closing_time = models.TimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email