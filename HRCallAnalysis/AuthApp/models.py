from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.validators import RegexValidator
from .validators import validate_mobile_no, validate_opo_id

class Role(models.Model):
    ADMIN = 'Admin'
    SUPERADMIN = 'SuperAdmin'
    USER = 'User'
    
    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (SUPERADMIN, 'SuperAdmin'),
        (USER, 'User'),
    ]
    
    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)
    
    def __str__(self):
        return self.name

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

    def get_by_natural_key(self, username):
        return self.get(
            models.Q(email=username) |
            models.Q(opo_id=username) |
            models.Q(mobile_no=username)
        )

class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    opo_id = models.CharField(
        max_length=50,
        unique=True,
        blank=True,
        null=True,
        validators=[validate_opo_id]
    )
    mobile_no = models.CharField(
        max_length=15,
        unique=True,
        blank=True,
        null=True,
        validators=[validate_mobile_no]
    )
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    objects = CustomUserManager()
    
    def __str__(self):
        return self.email
    
    def has_perm(self, perm, obj=None):
        return self.is_superuser
    
    def has_module_perms(self, app_label):
        return self.is_superuser

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'