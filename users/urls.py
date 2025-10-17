# users/urls.py
from django.urls import path
from .views import (
    RegisterUserView, RegisterAdminView,
    LoginJWTView, LoginSessionView, LogoutSessionView,
    AdminOnlyView, UserView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('register-admin/', RegisterAdminView.as_view(), name='register-admin'),
    path('login-jwt/', LoginJWTView.as_view(), name='login-jwt'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login-session/', LoginSessionView.as_view(), name='login-session'),
    path('logout-session/', LogoutSessionView.as_view(), name='logout-session'),

    path('admin-only/', AdminOnlyView.as_view(), name='admin-only'),
    path('me/', UserView.as_view(), name='me'),
]
