# Generated by Django 4.2.1 on 2023-05-16 09:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Application', '0007_uploadedfile_book_cover_uploadedfile_user_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='uploadedfile',
            name='visibility',
        ),
    ]