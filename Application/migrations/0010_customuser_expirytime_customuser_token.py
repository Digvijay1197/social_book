# Generated by Django 4.2.1 on 2023-05-22 11:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Application', '0009_alter_uploadedfile_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='expiryTime',
            field=models.TimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='token',
            field=models.CharField(blank=True, null=True, unique=True),
        ),
    ]