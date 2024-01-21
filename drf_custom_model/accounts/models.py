from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)

class MyAccountManager(BaseUserManager):
    def create_user(self,username,email,password=None):
        if username is None:
            raise TypeError("Users must have username.")
        if email is None:
            raise TypeError("Users must have email.")
        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )
        user.set_password(password)
        #user.save(using=self._db)
        user.save()
        #return user

    def create_superuser(self,username,email,password=None):
        if password is None:
            raise TypeError("Password should not be none.")
        user = self.create_user(
            username,
            email,
            password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        #user.save(using=self._db)
        user.save()
        return user


class Account(AbstractBaseUser, PermissionsMixin):
    username        = models.CharField(max_length=50, unique=True, verbose_name="email")
    email           = models.EmailField(max_length=50, unique=True)
    last_login      = models.DateTimeField(auto_now=True)
    is_admin        = models.BooleanField(default=False)
    is_active       = models.BooleanField(default=True)
    is_staff        = models.BooleanField(default=False)
    is_superuser    = models.BooleanField(default=False)
    hide_email      = models.BooleanField(default=True)

    USERNAME_FIELD  = 'email'
    REQUIRED_FIELDS = ['username']

    objects=MyAccountManager()

    def has_perm(self,perm,obj=None):
        return self.is_admin

    def has_module_perms(self,app_label):
        return True

    def __str__(self):
        return self.email
    
    def tokens(self):
        return ''
    



