from django.contrib import admin

# Register your models here.
from app.models import CustomUser

admin.site.register(CustomUser)