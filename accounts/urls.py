from django.urls import path
from .views import LoginView, RegisterView, LogoutView, PasswordResetView, ForgotPasswordView, \
    RestorePasswordConfirmView, ActivateView, ResendActivationCodeView, DeactivateAccountView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),

    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('restore-password/<uidb64>/<token>/', RestorePasswordConfirmView.as_view(), name='restore-password'),

    path('activate/<code>/', ActivateView.as_view(), name='activate-code'),
    path('resent-activation-code/', ResendActivationCodeView.as_view(), name='resend-activation-code'),

    path('deactivate/', DeactivateAccountView.as_view(), name='deactivate'),
]
