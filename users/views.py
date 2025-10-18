# users/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from rest_framework.decorators import api_view, permission_classes

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterUserView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        data = request.data.copy()
        data.setdefault('role', 'user')
        serializer = RegisterSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RegisterAdminView(APIView):
    permission_classes = [permissions.AllowAny]  # you can restrict this if you want
    def post(self, request):
        data = request.data.copy()
        data['role'] = 'admin'
        serializer = RegisterSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            # optionally make staff/superuser flags
            user.is_staff = True # Set staff status before the first save
            user.save(update_fields=['is_staff'])
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED) # Return the serialized user
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginJWTView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            tokens = get_tokens_for_user(user)
            return Response(tokens)
        return Response({"detail":"Invalid"}, status=status.HTTP_401_UNAUTHORIZED)

class LoginSessionView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            login(request, user)
            return Response({"detail": "session login successful"}, status=status.HTTP_200_OK)
        return Response({"detail":"Invalid"}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutSessionView(APIView):
    def post(self, request):
        logout(request)
        return Response({"detail": "logged out"}, status=status.HTTP_200_OK)

# Protected endpoints
class AdminOnlyView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        if request.user.role != 'admin':
            return Response({"detail":"Forbidden - admin only"}, status=status.HTTP_403_FORBIDDEN)
        return Response({"detail":"Hello Admin", "user": UserSerializer(request.user).data})

class UserView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        return Response({"detail":"Hello User", "user": UserSerializer(request.user).data})
