HOME_PATH_BASE_NAME = 'home'
# ACCOUNTS VARIABLE
ACCOUNT_REGISTER_SUCCESS = 'Successfully registered. To activate please verify email.'
ACCOUNT_ACTIVATION_SUCCESS = 'Successfully account activated.'
ACCOUNT_ACTIVATION_FAILED = 'Activation code is expired. You can apply for resend code for activation.'
ACCOUNT_MODEL_BACKEND = 'django.contrib.auth.backends.ModelBackend'
ACCOUNT_LOGIN_SUCCESS = 'Successfully logged in.'
ACCOUNT_LOGIN_FAILED = 'Invalid credentials.'
ACCOUNT_LOGOUT_SUCCESS = 'Successfully logged out.'
ACCOUNT_RESENT_ACTIVATION = 'Re-sent account activation code.'
ACCOUNT_PASSWORD_RESET_SUCCESS = 'Password reset successful. You must login again.'
ACCOUNT_PASSWORD_RESET_LINK_SENT = 'Link for password reset sent to your email.'
ACCOUNT_PASSWORD_RESET_INVALID_LINK = 'This link is invalid or expired. You can apply for resend.'
ACCOUNT_DEACTIVATION_SUCCESS = 'Successfully account deactivated.'

# ACCOUNTS TEMPLATE PATH VARIABLE
ACCOUNT_LOGIN_PAGE = 'accounts/login.html'
ACCOUNT_REGISTER_PAGE = 'accounts/register.html'
ACCOUNT_PASSWORD_RESET_PAGE = 'accounts/password_reset.html'
ACCOUNT_FORGOT_PASSWORD_PAGE = 'accounts/forgot_password.html'
ACCOUNT_RESTORE_PASSWORD_PAGE = 'accounts/restore_password.html'
ACCOUNT_RESEND_ACTIVATION_CODE_PAGE = 'accounts/resend_activation_code.html'

# ACCOUNTS SOCIAL AUTH PROVIDERS
ACCOUNT_SOCIAL_AUTH_GITHUB = 'github'
ACCOUNT_SOCIAL_AUTH_TWITTER = 'twitter'
ACCOUNT_SOCIAL_AUTH_FACEBOOK = 'facebook'
ACCOUNT_SOCIAL_AUTH_GOOGLE = 'google-oauth2'

# ACCOUNTS FORMS VARIABLES
ACCOUNT_ALREADY_EXIST_EMAIL = 'This email is already registered.'
ACCOUNT_PASSWORD_NOT_MATCHING = 'The password is not matching.'
ACCOUNT_EMAIL_NOT_REGISTERED = 'This email is not registered.'
ACCOUNT_EMAIL_NOT_VERIFIED = 'The email is not verified.'
ACCOUNT_INCORRECT_PASSWORD = 'The password is incorrect.'
ACCOUNT_ALREADY_ACTIVE_EMAIL = 'This email is already active.'
ACCOUNT_PASSWORD_REQUIRED = 'Password is Required.'
