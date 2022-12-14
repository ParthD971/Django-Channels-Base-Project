from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

import logging
from .tasks import send_mail_task

logger = logging.getLogger('accounts')


def send_mail(to, template, context):
    html_content = render_to_string(f'accounts/emails/{template}.html', context)
    # send mail using celary
    send_mail_task.delay(context['subject'], html_content, to)


def send_activation_email(request, email, code):
    context = {
        'subject': _('Profile activation'),
        'uri': request.build_absolute_uri(reverse('activate-code', kwargs={'code': code})),
    }
    logger.info('Sending activation mail...')
    send_mail(email, 'activate_profile', context)


def send_reset_password_email(request, email, token, uid):
    context = {
        'subject': _('Restore password'),
        'uri': request.build_absolute_uri(
            reverse('restore-password', kwargs={'uidb64': uid, 'token': token})),
    }
    logger.info('Sending reset password mail...')
    send_mail(email, 'restore_password_email', context)
