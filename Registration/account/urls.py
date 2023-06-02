from django.urls import path, include
from account.views import UserRegistrationView, UserLoginView, UserProfileView, \
    UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, VerifyOtp


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name= 'login'),
    path('verify/', VerifyOtp.as_view(), name= 'verify'),
    path('profile/', UserProfileView.as_view(), name= 'profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name= 'changepassword'),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view(), 
         name= 'send-reset-password-email'),
    path('reset_password/', UserPasswordResetView.as_view(), 
         name= 'reset-password'),
]