from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Role

class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no', 'role', 'is_active', 'is_staff', 'created_by')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'created_by')
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'opo_id', 'mobile_no', 'designation', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at', 'created_by')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2',
                      'opo_id', 'mobile_no', 'role', 'designation', 'is_active', 'is_staff'),
        }),
    )
    
    def save_model(self, request, obj, form, change):
        # Set created_by to the current user when creating a new user
        if not obj.pk:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Role)