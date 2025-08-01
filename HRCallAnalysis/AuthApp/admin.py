from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Role

class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no', 'role', 'is_active', 'is_staff')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)
    readonly_fields = ('created_at', 'updated_at', 'last_login')
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'opo_id', 'mobile_no', 'designation', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2',
                      'opo_id', 'mobile_no', 'role', 'designation', 'is_active', 'is_staff'),
        }),
    )

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Role)