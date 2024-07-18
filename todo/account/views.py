from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import viewsets, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework import viewsets
from .serializers import UserSerializer, TodosSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer
from django.contrib.auth import authenticate
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from .models import Todo,UserData
from django.shortcuts import get_object_or_404


class MyTokenObtainPairViews(TokenObtainPairView):
    serializer_class=MyTokenObtainPairSerializer

# view for registering users
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class TodosViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TodosSerializer

    def get_queryset(self):
        return Todo.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def check_object_permissions(self, request, obj):
        if obj.user != request.user:
            raise PermissionDenied("You do not have permission to access this todo.")
    # authentication_classes=[TokenAuthentication]
    # pagination_class=[PageNumberPagination]
    # PageNumberPagination.page_size=5
    # lookup_field='user__pk'
    
