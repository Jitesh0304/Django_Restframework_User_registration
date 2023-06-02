from rest_framework import serializers
from account.models import User
from xml.dom import ValidationErr
from django.core.exceptions import ValidationError
from account.utils import *


        ## user registration 
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style = {'input_type':'password'}, write_only =True)
    class Meta:
        model = User
        fields = ['email','name','password','password2','otp']
        extra_kwargs = {
            'password':{'write_only':True},
        }
            ## validate both password is same or not
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match')
        return data
                ## if the validation is successfull then create that user
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)
    


            ## for OTP verification
class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    class Meta:
        fields = ['email','otp']



                ## This is for login page
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email','password'] 




            ## this is for perticular user profile 
class UserProfileSeralizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','email','name']




            ## this is for password change
class UserChangePassword(serializers.Serializer):
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    class Meta:
        fields = ['password','password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match')
        user.set_password(password)
        user.save()
        return data
    



            ## this is for forgot password
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length =255)
    class Meta:
        fileds = ['email']

    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email =email).exists():
            user = User.objects.get(email= email)
            reset_pass_email(user.email)
            return "Successful"
        else:
            raise ValidationErr('You are not a Registered user')
        


            ## this is for reset password
class UserPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length= 255)
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    otp = serializers.CharField()
    class Meta:
        fields = ['email','password','password2','otp']

    def validate(self, data):
        try:
            email = data.get('email')
            password = data.get('password')
            password2 = data.get('password2')
            otp = data.get('otp')
            user = User.objects.get(email=email)
            if password != password2:
                raise serializers.ValidationError('Password and Confirm password does not match')
            if user.otp != otp:
                raise serializers.ValidationError('Wrong OTP')
            if user.otp == otp:
                user.is_verified = True
                user.set_password(password)
                user.save()
                return data
        except User.DoesNotExist:
            raise serializers.ValidationError('No user is present with this email')
        except Exception as e:
            raise serializers.ValidationError(str(e))
