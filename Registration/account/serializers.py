from rest_framework import serializers
from account.models import User
from account.utils import reset_pass_otp_email
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer, TokenBlacklistSerializer ## TokenVerifySerializer
from rest_framework_simplejwt.tokens import RefreshToken # AccessToken
import jwt
from decouple import config
from django.utils import timezone



class CustomTokenBlacklistSerializer(TokenBlacklistSerializer):
    def validate(self, attrs):
        refresh = attrs.get("refresh")
        token = RefreshToken(refresh).blacklist()
        return "success"

# class CustomTokenBlacklistSerializer(TokenBlacklistSerializer):
#     def validate(self, attrs):
#         return super().validate(attrs)

    ## custom token generator
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
        ## send the user data to get the token
    def get_token(cls, user):
            ## check the user is verify or not
        if user is not None and user.is_verified:
                ## generate token for the user.. it will give you refresh and access token
            token = super().get_token(user)
                # Add username and email to the token payload
                ## add extra field in the payload
            token['username'] = user.fullName
            token['email'] = user.email
            token['organization'] = user.organization
            return token
        else:
            raise serializers.ValidationError('You are not verified')
    # def validate(self, attrs):
    #     data = super().validate(attrs)
    #           # Add username and email to the response data
    #     data['fullName'] = self.user.fullName
    #     data['email'] = self.user.email
    #     data['organization'] = self.user.organization
    #     return data


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        ## call super() to get the access token and refresh token
        data = super().validate(attrs)
        ## validate the input data ( attrs )
        ## take the refresh token from the attrs
        refresh_token = RefreshToken(attrs['refresh'])
        ## take the user email from the refresh token
        email = refresh_token.payload.get('email')
        try:
            ## take the user details from the database
            user = User.objects.get(email = email)
            ## decode the generated jwt token
            decodeJTW = jwt.decode(str(data['access']), config('DJANGO_SECRET_KEY'), algorithms=["HS256"])
                # add payload here
            decodeJTW['username'] = str(user.fullName)
            decodeJTW['email'] = str(user.email)
            decodeJTW['organization'] = str(user.organization)
            ## encode the modified jwt token
            encoded = jwt.encode(decodeJTW, config('DJANGO_SECRET_KEY'), algorithm="HS256")
            ## replace the access token with the modified one
            data['access'] = encoded
            data['is_manager']= user.is_manager
            data['team_leader']= user.team_leader
            data['technical_support']= user.technical_support
            data['supervisor']= user.supervisor
            data['labeler']= user.labeler
            data['reviewer']= user.reviewer
            data['approver']= user.approver
            user.last_login = timezone.now()
            user.save()
            ## return the newly generated token
            return data
        except:
            return data




        ## user registration 
class UserRegistrationSerializer(serializers.ModelSerializer):
        ## password field is write only
    password2 = serializers.CharField(required=True,style = {'input_type':'password'}, write_only =True)
    class Meta:
        model = User
        fields = ['email','fullName','organization','password','password2','is_admin','team_leader',
                  'technical_support','supervisor','labeler','reviewer','approver','is_manager']
        extra_kwargs = {
            'password':{'write_only':True},            ## password => write_only field
        }

            ## validate both passwords are same or not
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        # user_role = data.get('user_role')
        # role = ["TeamLeader", "TechnicalSupport", "Supervisor", "Labeler", "Reviewer", "Approver", "Admin"]
        # if user_role not in role:
        #     raise serializers.ValidationError(f"User role should be {role}")
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match.....')
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long....")
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
        fields = ['email','password']               ## this two fields we need during login




            ## this is for perticular user profile 
class UserProfileSeralizer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%d/%m/%Y ")
    last_login = serializers.DateTimeField(format="%d/%m/%Y %H:%M:%S")
    class Meta:
        model = User
        fields = ['email','fullName','organization','created_at','last_login','is_admin','team_leader',
                  'technical_support','supervisor','labeler','reviewer','approver','is_manager']
    
    def to_representation(self, instance):
        user = self.context.get('user')
        data = super().to_representation(instance)
        if not user.is_manager:
            data.pop("last_login")
        return data


            ## this is for password change
class UserChangePassword(serializers.Serializer):
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only =True)
    class Meta:
        fields = ['password','password2']

        ## validate both passwords are same or not
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
            ## take the user data from context send from views class
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match')
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long....")
            ## set the new password in user account
        user.set_password(password)
        # print(user.check_password())
        user.save()
        return data




            ## this is for forgot password
class SendPasswordResetEmailSerializer(serializers.Serializer):
        ## for forgot password .. user email is required
    email = serializers.EmailField(max_length =255)
    class Meta:
        fileds = ['email']

        ## validate the email ... check any user present with this email or not
    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email= email, is_verified= True).exists():
            user = User.objects.get(email= email)
                ## call the custom forgot password function and sent the otp to the user account
            reset_pass_otp_email(user.email)
            return "Successful"
        else:
            raise serializers.ValidationError('You are not a Registered user or you have not verified your account...')



            ## this is for reset password
class UserPasswordResetSerializer(serializers.Serializer):
        ## for reset password these fields are required
    email = serializers.EmailField(max_length= 255)
    password = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length= 255, style= {'input_type':'password'}, write_only=True)
    otp = serializers.CharField()
    class Meta:
        fields = ['email','password','password2','otp']

        ## validate the user details 
    def validate(self, data):
        try:
            email = data.get('email')
            password = data.get('password')
            password2 = data.get('password2')
            otp = data.get('otp')
            user = User.objects.get(email=email, is_verified=False)
            if password != password2:
                raise serializers.ValidationError('Password and Confirm password does not match')
            if len(password) < 8:
                raise serializers.ValidationError("Password must be at least 8 characters long....")
            if user.otp != otp:
                raise serializers.ValidationError('Wrong OTP')
            if user.otp == otp:
                ## if everything is verified make the user verified
                user.is_verified = True
                ## save the new password in user account
                user.set_password(password)
                user.save()
                return data
        except User.DoesNotExist:
            raise serializers.ValidationError('No user is present with this email.. Or your account is verified')
        except Exception as e:
            raise serializers.ValidationError(str(e))
            # raise serializers.ValidationError("Something went wrong")






        ## manager can change the role of an employee
# class ChangeUserRoleSerializer(serializers.Serializer):
#     email = serializers.EmailField(max_length= 255)
#     fullName = serializers.CharField(max_length=100)                ##
#     organization = serializers.CharField(max_length=100)
#     user_role = serializers.CharField(max_length=50)
#     is_manager = serializers.BooleanField()
#     class Meta:
#         fields = ['email','fullName','organization','is_manager',]
        ## manager can change the role of an employee
class ChangeUserRoleSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length= 255)
    class Meta:
        model = User
        fields = ['email','is_admin','team_leader',
                  'technical_support','supervisor','labeler','reviewer','approver','is_manager']

        # validate the data
    def validate(self, attrs):
        email = attrs.get('email')
        req_user = self.context['request'].user
        try:
            user = User.objects.get(email= email, is_verified=True)
            # user = User.objects.get(email= email, organization=req_user.organization)
        except Exception:
            raise serializers.ValidationError("User is not present or User is not a verified user")
        if req_user.organization != user.organization:
            raise serializers.ValidationError("You have no permissions to change other oganization user data....")
                    ## check the employee of that organization is verified or not
        return attrs


    def update(self, instance, validated_data):
        # print(validated_data)
        # print(instance)
        instance.is_manager = validated_data.get('is_manager', instance.is_manager)
        instance.is_admin = validated_data.get('is_admin', instance.is_admin)
        instance.team_leader = validated_data.get('team_leader', instance.team_leader)
        instance.technical_support = validated_data.get('technical_support', instance.technical_support)
        instance.supervisor = validated_data.get('supervisor', instance.supervisor)
        instance.labeler = validated_data.get('labeler', instance.labeler)
        instance.reviewer = validated_data.get('reviewer', instance.reviewer)
        instance.approver = validated_data.get('approver', instance.approver)
        instance.save()
        return instance



        ## manager can create user account
class UserRegistrationByTeamLeaderSerializer(serializers.ModelSerializer):
                ## we need to mension this because for varification purpose we have created this
    password2 = serializers.CharField(required=True,style = {'input_type':'password'}, write_only =True)
    class Meta:
        model = User
        fields = ['email','fullName','organization','password','password2','is_admin','team_leader',
                  'technical_support','supervisor','labeler','reviewer','approver','is_manager']          ## mension the required fileds (( otp  ))
        extra_kwargs = {
            'password':{'write_only':True},            ## password => write_only field
        }

            ## validate both passwords are same or not
    def validate(self, data):
        # userRole = data.get('user_role')
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context['request'].user
            ## check the manager organization and the new user organization is same or not
        if user.organization != data.get('organization'):
            raise serializers.ValidationError("You can not create user for other organization")
        if password != password2:
            raise serializers.ValidationError('Password and Confirm password does not match')
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long....")
            ## user role options
        # role = ["TeamLeader", "TechnicalSupport", "Supervisor", "Labeler", "Reviewer", "Approver", "Admin"]
        # if userRole not in role:
        #     raise serializers.ValidationError(f"User role should be {role}")
        return data

                ## if the validation is successfull then create that user
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)