from django.core.mail import send_mail
import random
from django.conf import settings
from .models import User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings



    ## send the verification otp to the user account
def sent_otp_by_email(email):
    subject = "Your account verification email.."
    # otp = random.randint(100000,999999)
    otp = 123456
    message = f"Your OTP for account verification is {otp}"
    email_from = settings.EMAIL_HOST_USER
        ## send the required dat and parameters in the send_email function
    send_mail(subject, message, email_from, [email])
    user_obj = User.objects.get(email=email)
        ## save the otp in the user table for verification
    user_obj.otp = otp
    user_obj.save()



## send the forgot password otp
def reset_pass_otp_email(email):
    subject = "Your account verification email.."
    # otp = random.randint(100000,999999)
    otp = 987654
    message = f"Your OTP for forgot password is {otp}"
    email_from = settings.EMAIL_HOST_USER
    ## send the required dat and parameters in the send_email function
    send_mail(subject, message, email_from, [email])
    user_obj = User.objects.get(email=email)
    ## save the otp in the user table for verification
    user_obj.otp = otp
    ## make the user unverified
    user_obj.is_verified = False
    user_obj.save()



    ## send the account activation link to the user email
# def send_activation_email(recipient_email, activation_url, host, uid, token):
def send_activation_email(recipient_email, activation_url, host):
    subject = 'Activate your Aaai tool account..'
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]

    # Load the HTML template
    ## send the HTML design page and activation link ... and use that link and create a button in the html page
    html_content = render_to_string('account/activation_email.html', {'activation_url': activation_url})
    # html_content = render_to_string('account/activation_email.html', {'activation_url': activation_url, 'uid':uid, 'token':token})

    # Create the email body with both HTML and plain text versions
    text_content = strip_tags(html_content)
    ## send the email to the user
    email = EmailMultiAlternatives(subject, text_content, from_email, to)
    email.attach_alternative(html_content, "text/html")
    email.send()




def send_forgot_pass_email(recipient_email, forgot_verify, host):
    subject = 'Reset your Aaai tool password'
    # subject = 'Reset your password'+host
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]
    html_content = render_to_string('account/forgot_pass.html', {'forgot_verify': forgot_verify})
    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject, text_content, from_email, to)
    email.attach_alternative(html_content, "text/html")
    email.send()