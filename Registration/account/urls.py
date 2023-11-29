from django.urls import path, include
from account.views import UserRegistrationView, UserLoginView, UserProfileView,AllUserProfileView, \
    UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, VerifyOtp, \
    CustomTokenObtainPairView, CustomTokenRefreshView, UserRegistrationByTeamLeaderView, ChanageUserRole, LogoutView, DeleteBlacklistAdOutstandingView
   ##  ResetPasswordView, ActivationConfirm, ForgotPasswordEmailSendView, ForgotPasswordEmailVerifyView,
from rest_framework_simplejwt.views import TokenVerifyView, TokenBlacklistView ## TokenObtainPairView, TokenRefreshView,


urlpatterns = [
    # path('gettoken/',TokenObtainPairView.as_view(), name= 'token_pair'),
    # path('refreshtoken/', TokenRefreshView.as_view(), name= 'token_resfresh'),
    path('gettoken/',CustomTokenObtainPairView.as_view(), name= 'token_pair'),
    path('refreshtoken/', CustomTokenRefreshView.as_view(), name= 'token_resfresh'),
    path('verifytoken/',TokenVerifyView.as_view(), name= 'token_verify'),
    path('blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('registerby/', UserRegistrationByTeamLeaderView.as_view(), name='registerby'),
    path('login/', UserLoginView.as_view(), name= 'login'),
    path('verify/', VerifyOtp.as_view(), name= 'verify'),
    path('profile/', UserProfileView.as_view(), name= 'profile'),
    path('allprofile/', AllUserProfileView.as_view(), name= 'allprofile'),
    path('changepassword/', UserChangePasswordView.as_view(), name= 'changepassword'),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view(), name= 'send_reset_password_email'),
    path('reset_password/', UserPasswordResetView.as_view(), name= 'reset_password'),
    path('changerole/', ChanageUserRole.as_view(), name= 'changerole'),
    path('logout/', LogoutView.as_view(), name= 'logout'),
    path('deletetoken/', DeleteBlacklistAdOutstandingView.as_view(), name= 'deletetoken'),
    # path('activate/', ActivationConfirm.as_view(), name='activate'),
    # path('activate/<str:uid>/<str:token>/', ActivationConfirm.as_view(), name='activate'),
    # path('forgotpass/', ForgotPasswordEmailSendView.as_view(), name='forgotpass'),
    # path('forgot_verify/<str:uid>/<str:token>/', ForgotPasswordEmailVerifyView.as_view(), name='forgot_verify'),
    # path('reset/', ResetPasswordView.as_view(), name='reset'),
]


