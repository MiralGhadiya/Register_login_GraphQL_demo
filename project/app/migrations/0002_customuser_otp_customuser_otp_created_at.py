# Generated by Django 5.0.6 on 2024-06-10 07:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='otp',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='otp_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
