from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
# from django.contrib.auth.hashers import make_password               ## this will convert the password to hashed    

class UserManager(BaseUserManager):
    def create_user(self, email, name, otp , password=None, password2 = None):             ##
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email = self.normalize_email(email),                  ## normalize the email 
            name = name, 
            otp = otp,  
        )
            ## set password => set the password fields
        user.set_password(password)
        user.save(using=self._db)       ## save the user in database
        return user
    
                    ## this is the hashed converter
        # hashed_password = make_password(password)
        # user.password = hashed_password
        # user.save(using=self._db)
        # return user

            ## create superuser using these fields...
    def create_superuser(self, email, name, otp, password=None):             ##
        user = self.create_user(
            email,
            password = password,
            name = name,                                                    ##   
            otp = otp,
        )

        user.is_admin = True 
        user.is_verified = True         
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='Email',                 ##
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)                ##
    is_verified = models.BooleanField(default= False)
    otp = models.CharField(max_length=4, null=True, blank=True)                     ##
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add= True)       ##
    updated_at = models.DateTimeField(auto_now=True)            ##

    objects = UserManager()                                     ##

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','otp']                         ##

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin                                        ##

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin