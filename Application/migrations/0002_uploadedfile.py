# Generated by Django 4.2.1 on 2023-05-12 11:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Application', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UploadedFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('visibility', models.BooleanField(default=True)),
                ('cost', models.DecimalField(blank=True, decimal_places=2, max_digits=8, null=True)),
                ('year_published', models.IntegerField(blank=True, null=True)),
                ('file', models.FileField(upload_to='uploaded_files/')),
            ],
        ),
    ]
