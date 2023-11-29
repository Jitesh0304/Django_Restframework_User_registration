from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from datetime import datetime
from django.utils import timezone




class UserManager(BaseUserManager):
    def create_user(self, email, fullName, organization, password=None,otp =None, password2 = None,is_admin=None,team_leader=None,
                    technical_support=None,supervisor=None, labeler=None,reviewer=None,approver=None,is_manager=None):             ## otp
        """
        Creates and saves a User with the given email, name ,
        otp  and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        if not fullName:
            raise ValueError('Users must provide his full name')
        if not organization:
            raise ValueError('Users must provide organization name')

        user = self.model(
            email = self.normalize_email(email),
            fullName = fullName,
            organization = organization,
            otp = otp,
            is_admin= is_admin,
            team_leader=team_leader,
            technical_support=technical_support,
            supervisor=supervisor,
            labeler=labeler,
            reviewer=reviewer,
            approver=approver,
            is_manager=is_manager

        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, fullName, organization, otp=None, password=None):             ## otp
        """
        Creates and saves a superuser with the given email, name,
        tc and password.
        """
        user = self.create_user(
            email,
            password = password,
            fullName = fullName,                                                    ##
            organization= organization,
            otp = otp,
            is_admin= True,
            team_leader= True,
            technical_support= True,
            supervisor= True,
            labeler= True,
            reviewer= True,
            approver= True,
            is_manager= True
        )
        user.is_superuser = True
        user.is_verified = True
        user.created_at = timezone.now()
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        primary_key=True,
        verbose_name='Email',
        max_length=255
    )
    fullName = models.CharField(max_length=100, unique=True)
    organization = models.CharField(max_length=100, blank=False, null= False)
    otp = models.CharField(max_length=6, null=True, blank=True, default="")
    created_at = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_manager = models.BooleanField(default=False)
    is_verified = models.BooleanField(default= False)
    is_superuser = models.BooleanField(default=False)

    is_admin = models.BooleanField(default=False)
    team_leader = models.BooleanField(default=False)
    technical_support = models.BooleanField(default=False)
    supervisor = models.BooleanField(default=False)
    labeler = models.BooleanField(default=False)
    reviewer = models.BooleanField(default=False)
    approver = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['fullName','organization']
    REQUIRED_FIELDS = ['fullName','organization']
    # ['is_admin','team_leader','technical_support','supervisor','labeler','reviewer','approver']
    def __str__(self):
        return self.email

    # def get_full_name(self):
    #     return self.fullName
    

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_superuser                                        ##


    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_superuser
        # return self.is_manager

