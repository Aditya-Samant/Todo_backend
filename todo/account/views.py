from rest_framework.views import APIView
from rest_framework import viewsets, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework import viewsets
from .serializers import *
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer
from .models import Todo,UserData
from .email import send_otp_via_mail
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework import status
from rest_framework.response import Response

class MyTokenObtainPairViews(TokenObtainPairView):
    serializer_class=MyTokenObtainPairSerializer
    

# view for registering users
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        send_otp_via_mail(serializer.data['email'])
        return Response(serializer.data)
    
class ResendOtp(APIView):
    def post(self,request):
        serializer=ResendOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email=serializer.data['email']
        user=UserData.objects.filter(email=email)
        if not user.exists():
            return Response({
                    "status":400,
                    "message":"invalid user "
                })
        send_otp_via_mail(email)
        return Response({
                    "status":200,
                    "message":"otp sent successfully"
                })
    
class VerifyOTPView(APIView):
    def post(self,request):
        data=request.data 
        serializer=VerifyOtpSerializer(data=data)
        if serializer.is_valid():
            email=serializer.data['email']
            otp=serializer.data['otp']
            user=UserData.objects.filter(email=email)
            if not user.exists():
                return Response({
                    "status":400,
                    "message":"invalid user "
                })
            if not otp==user[0].otp:
                return Response({
                    "status":400,
                    "message":"invalid otp "
                })
            user=user.first()
            if user.is_active==True:
                return Response({
                    "status":200,
                    "message":"user is already verified"
                })
            user.is_active=True
            user.otp = None
            user.save()
            return Response({
                    "status":200,
                    "message":"user verified successfully"
                })
        return Response({
                    "status":400,
                    "message":serializer.errors
                }) 

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = UserData.objects.filter(email=email).first()
            if user:
                send_otp_via_mail(email)
                return Response({
                    "status": 200,
                    "message": "OTP sent to your email for password reset"
                })
            return Response({
                "status": 404,
                "message": "User with this email does not exist"
            })
        return Response({
            "status": 400,
            "message": serializer.errors
        })
    
class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            
            user = UserData.objects.filter(email=email).first()
            if not user:
                return Response({
                    "status": 404,
                    "message": "User with this email does not exist"
                })
            
            if user.otp != otp:
                return Response({
                    "status": 400,
                    "message": "Invalid OTP"
                })
            
            user.set_password(new_password)
            user.otp = None  # Clear the OTP after successful password reset
            user.save()
            
            return Response({
                "status": 200,
                "message": "Password reset successful"
            })
        
        return Response({
            "status": 400,
            "message": serializer.errors
        })

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
    
    
