import random
from datetime import datetime, timedelta
from django.utils import timezone
from app.models import CustomUser
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp,user):
    otp = generate_otp()
    user.otp = otp
    user.otp_created_at = timezone.now()
    user.save()
    
    subject = 'Your OTP for Login'
    message = f'Your OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)
    
    print(f"OTP for user {user.email}: {otp}")

def verify_otp(user, otp):
    print(f"Verifying OTP. User OTP: {user.otp}, Provided OTP: {otp}")
    if user.otp == otp and timezone.now() <= user.otp_created_at + timedelta(minutes=10):
        user.otp = None
        user.otp_created_at = None
        user.save()
        return True
    return False
