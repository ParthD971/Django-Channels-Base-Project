from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View

from accounts.forms import LoginForm, RegisterForm, PasswordResetForm, ForgotPasswordForm, ResendActivationCodeForm, \
    RestorePasswordForm
from accounts.models import User, Activation
from accounts.utils import send_activation_email, send_reset_password_email
from core.constants import ACCOUNT_LOGIN_PAGE, ACCOUNT_MODEL_BACKEND, ACCOUNT_LOGIN_FAILED, ACCOUNT_REGISTER_PAGE, \
    ACCOUNT_PASSWORD_RESET_SUCCESS, ACCOUNT_PASSWORD_RESET_INVALID_LINK, ACCOUNT_ACTIVATION_FAILED, \
    ACCOUNT_RESEND_ACTIVATION_CODE_PAGE, ACCOUNT_RESTORE_PASSWORD_PAGE, ACCOUNT_FORGOT_PASSWORD_PAGE, \
    ACCOUNT_PASSWORD_RESET_PAGE, HOME_PATH_BASE_NAME, ACCOUNT_LOGIN_SUCCESS, ACCOUNT_REGISTER_SUCCESS, \
    ACCOUNT_LOGOUT_SUCCESS, ACCOUNT_FORGOT_PASSWORD_LINK_SENT, ACCOUNT_PASSWORD_RESTORE_SUCCESS, \
    ACCOUNT_ACTIVATION_SUCCESS, ACCOUNT_ACTIVATION_LINK_SENT, ACCOUNT_DEACTIVATION_SUCCESS


class LoginView(View):
    """
    description: This is user login view.
    GET request will display Login Form in login.html page.
    POST request will make user login if details is valid else login form with error is displayed.
    permission: Must Be Anonymous user
    """
    def get(self, request):
        form = LoginForm()
        return render(request, template_name=ACCOUNT_LOGIN_PAGE, context={'form': form})

    def post(self, request):
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            if user := authenticate(email=email, password=password):
                login(request, user, backend=ACCOUNT_MODEL_BACKEND)
                messages.success(request, ACCOUNT_LOGIN_SUCCESS)
                return redirect(HOME_PATH_BASE_NAME)
            messages.error(request, ACCOUNT_LOGIN_FAILED)
        return render(request, template_name=ACCOUNT_LOGIN_PAGE, context={'form': form})


class RegisterView(View):
    """
    description: This is user register view.
    GET request will display Register Form in register.html page.
    POST request will make user registered if details is valid else register
    form with error is displayed.
    permission: Must Be Anonymous user
    """
    def get(self, request):
        form = RegisterForm()
        return render(request, template_name=ACCOUNT_REGISTER_PAGE, context={'form': form})

    def post(self, request):
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            code = user.get_activation_code()
            send_activation_email(request, user.email, code)
            messages.success(request, ACCOUNT_REGISTER_SUCCESS)
            return redirect(HOME_PATH_BASE_NAME)
        return render(request, template_name=ACCOUNT_REGISTER_PAGE, context={'form': form})


class LogoutView(LoginRequiredMixin, View):
    """
    description: This is user logout view.
    GET request will log out user and redirects to home page.
    permission: Must Be LoggedIn user
    """
    def get(self, request):
        logout(request)
        messages.success(request, ACCOUNT_LOGOUT_SUCCESS)
        return redirect(HOME_PATH_BASE_NAME)


class PasswordResetView(LoginRequiredMixin, View):
    def get(self, request):
        form = PasswordResetForm()
        return render(request, template_name=ACCOUNT_PASSWORD_RESET_PAGE, context={'form': form})

    def post(self, request, *args, **kwargs):
        form = PasswordResetForm(request.POST, user=request.user)

        if form.is_valid():
            form.save(user=request.user)
            logout(request)
            messages.success(request, message=ACCOUNT_PASSWORD_RESET_SUCCESS)
            return redirect(HOME_PATH_BASE_NAME)
        return render(request, template_name=ACCOUNT_PASSWORD_RESET_PAGE, context={'form': form})


class ForgotPasswordView(View):
    def get(self, request):
        form = ForgotPasswordForm()
        return render(request, template_name=ACCOUNT_FORGOT_PASSWORD_PAGE, context={'form': form})

    def post(self, request, *args, **kwargs):
        form = ForgotPasswordForm(request.POST)

        if form.is_valid():
            user = User.objects.get(email=form.cleaned_data.get('email'))
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            send_reset_password_email(self.request, user.email, token, uid)
            messages.success(request, ACCOUNT_FORGOT_PASSWORD_LINK_SENT)
            return redirect(HOME_PATH_BASE_NAME)
        return render(request, template_name=ACCOUNT_FORGOT_PASSWORD_PAGE, context={'form': form})


class RestorePasswordConfirmView(View):
    def get(self, request, *args, **kwargs):
        form = RestorePasswordForm()
        return render(request, template_name=ACCOUNT_RESTORE_PASSWORD_PAGE, context={'form': form})

    def post(self, request, uidb64=None, token=None, *args, **kwargs):
        form = RestorePasswordForm(request.POST)
        if form.is_valid():
            try:
                uid = urlsafe_base64_decode(uidb64)
                user = User.objects.get(pk=uid)
                if default_token_generator.check_token(user, token):
                    form.save(user=user)
                    logout(request)
                    messages.success(request, ACCOUNT_PASSWORD_RESTORE_SUCCESS)
                    return redirect(HOME_PATH_BASE_NAME)
                messages.error(request, ACCOUNT_PASSWORD_RESET_INVALID_LINK)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                messages.error(request, ACCOUNT_PASSWORD_RESET_INVALID_LINK)
            finally:
                return redirect(HOME_PATH_BASE_NAME)
        return render(request, template_name=ACCOUNT_RESTORE_PASSWORD_PAGE, context={'form': form})


class ActivateView(View):
    def get(self, request, code=None, *args, **kwargs):
        act = get_object_or_404(Activation, code=code)

        if act.is_valid():
            # Activate profile and Remove the activation record
            act.activate()
            messages.success(request, ACCOUNT_ACTIVATION_SUCCESS)
        else:
            messages.error(request, ACCOUNT_ACTIVATION_FAILED)
        return redirect(HOME_PATH_BASE_NAME)


class ResendActivationCodeView(View):
    def get(self, request):
        form = ResendActivationCodeForm()
        return render(request, template_name=ACCOUNT_RESEND_ACTIVATION_CODE_PAGE, context={'form': form})

    def post(self, request, *args, **kwargs):
        form = ResendActivationCodeForm(request.POST)

        if form.is_valid():
            user = User.objects.get(email=form.cleaned_data.get('email'))
            code = user.get_activation_code()
            send_activation_email(request, user.email, code)
            messages.success(request, ACCOUNT_ACTIVATION_LINK_SENT)
            return redirect(HOME_PATH_BASE_NAME)
        return render(request, template_name=ACCOUNT_RESEND_ACTIVATION_CODE_PAGE, context={'form': form})


class DeactivateAccountView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        user.is_active = False
        user.save()
        logout(request)
        messages.success(request, ACCOUNT_DEACTIVATION_SUCCESS)
        return redirect(HOME_PATH_BASE_NAME)
