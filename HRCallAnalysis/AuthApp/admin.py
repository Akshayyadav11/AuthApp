from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils import timezone
from django.utils.html import format_html
from .models import CustomUser, Role

# Set the timezone to IST
IST = timezone.get_fixed_timezone(330)  # UTC+5:30


admin.site.site_header = 'HR Portal'       # Header/title
admin.site.site_title = 'Admin' # Browser tab title
admin.site.index_title = 'Welcome to HR Portal'   # Subtitle on index page

class IsDeletedFilter(admin.SimpleListFilter):
    title = 'is deleted'
    parameter_name = 'is_deleted'

    def lookups(self, request, model_admin):
        return (
            ('1', 'Yes'),
            ('0', 'No'),
        )

    def queryset(self, request, queryset):
        if self.value() == '1':
            return queryset.filter(is_deleted=True)
        if self.value() == '0':
            return queryset.filter(is_deleted=False)
        return queryset

class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no', 'role', 'is_active', 'created_by', 'is_deleted', 'raw_created_at', 'raw_updated_at')
    list_filter = (IsDeletedFilter, 'role', 'is_active', 'is_staff', 'created_at', 'updated_at')
    
    def raw_created_at(self, obj):
        if obj.created_at:
            return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
        return "-"
    raw_created_at.admin_order_field = 'created_at'
    raw_created_at.short_description = 'Created At'
    
    def raw_updated_at(self, obj):
        if obj.updated_at:
            return obj.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        return "-"
    raw_updated_at.admin_order_field = 'updated_at'
    raw_updated_at.short_description = 'Updated At'
    search_fields = ('email', 'first_name', 'last_name', 'opo_id', 'mobile_no')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'created_by', 'is_deleted')
    
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
    
    def delete_queryset(self, request, queryset):
        # Override delete_queryset to perform soft delete
        for obj in queryset:
            obj.is_deleted = True
            obj.save()
    
    def delete_model(self, request, obj):
        # Override delete_model to perform soft delete
        obj.is_deleted = True
        obj.save()
    
    def get_queryset(self, request):
        # Get the base queryset
        qs = super().get_queryset(request)
        
        # Check if we're filtering for deleted users
        if request.GET.get('is_deleted') == '1':
            return qs.filter(is_deleted=True)
        elif request.GET.get('is_deleted') == '0':
            return qs.filter(is_deleted=False)
            
        # By default, show all users
        return qs

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Role)