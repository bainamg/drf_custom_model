# Generated by Django 5.0.1 on 2024-01-20 15:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_account_hide_email_alter_account_is_active_and_more'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Account',
            new_name='Accounts',
        ),
    ]
