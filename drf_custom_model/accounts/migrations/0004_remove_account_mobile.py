# Generated by Django 5.0.1 on 2024-01-20 12:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_account_mobile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='account',
            name='mobile',
        ),
    ]
