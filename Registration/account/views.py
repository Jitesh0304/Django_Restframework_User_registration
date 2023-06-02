from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSeralizer,\
      UserChangePassword, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, VerifyOtpSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .utils import *


    ## send customize JWT token .... You can add user details in the JWT pay_load
import jwt
from decouple import config

def get_tokens_for_user(user):
    refreshToken = RefreshToken.for_user(user)
    accessToken = refreshToken.access_token
        ## decode the JWT .... 
    decodeJTW = jwt.decode(str(accessToken), config('SECRET_KEY'), algorithms=["HS256"])
        # add payload here!!
    decodeJTW['user'] = str(user)
    decodeJTW['name'] = str(user.name)
        #encode
    encoded = jwt.encode(decodeJTW, config('SECRET_KEY'), algorithm="HS256")
    return {
        'refresh': str(refreshToken),
        'access': str(encoded),
    }

    
    ## create new user 
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format =None):
        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            sent_otp_by_email(serializer.data['email'])
            return Response({'msg':'Registarion Successful'}, status.HTTP_201_CREATED)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)



        ## verify OTP .. If OTP is correct then make the ((user.is_verify = True))
class VerifyOtp(APIView):
    def post(self, request):
        try:
            data = request.data 
            serializer = VerifyOtpSerializer(data= data)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']
                user = User.objects.filter(email= email)
                if not user.exists():
                    return Response({'msg':'Invalid Email'}, status= status.HTTP_404_NOT_FOUND)
   
                else:
                    user = User.objects.get(email=email)
                    if user.otp != otp:
                        return Response({'msg':'Wrong OTP'}, status= status.HTTP_400_BAD_REQUEST)
                    if user.otp == otp:
                        # print(user.is_verified)       ## is_verified is a field in User model.. Bydefault it is false
                        user.is_verified = True
                        user.save()
                        return Response({'msg':'Account verified'}, status= status.HTTP_200_OK) 
       
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)        
        except Exception as e:
            return Response({'msg':e})




        ## This is for User login
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        serializer = UserLoginSerializer(data= request.data)
        if serializer.is_valid(raise_exception= True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email= email, password = password)
            if user is not None:
                user = User.objects.get(email= email)
                if user.is_verified == True:
                    token = get_tokens_for_user(user)
                    return Response({'token':token, 'msg':'Login successful'}, status= status.HTTP_200_OK)
                else:
                    return Response({'msg':'User is not verified'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error':{'non_field_errors':['Email or Password is not Valid']}},
                                status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)    


            ## this is for perticular user profile view
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format= None):
        serializer = UserProfileSeralizer(request.user)
        return Response(serializer.data, status= status.HTTP_200_OK)


            ## this is for password change
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format= None):
        serializer = UserChangePassword(data = request.data, context ={'user':request.user})
        if serializer.is_valid(raise_exception= True):
            return Response({'msg':'Password Changed Successfully'}, status.HTTP_200_OK)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
    

        ## this is for sending email to the user
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        serializer = SendPasswordResetEmailSerializer(data = request.data)
        if serializer.is_valid(raise_exception= True):
            return Response({'msg':'Password Reset OTP has been sent to your Email. Please check your Email'},
                            status= status.HTTP_200_OK)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
    

            ## this is for reset the password
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format= None):
        serializer = UserPasswordResetSerializer(data= request.data)
        if serializer.is_valid(raise_exception= True):
            return Response({'msg':'Password reset successfully'}, status= status.HTTP_200_OK)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
