from django.contrib import admin
from account.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken


from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin





class UserModelAdmin(BaseUserAdmin):
    ## diplay list
    list_display = ('email', 'fullName', 'organization', 'otp','is_admin','is_verified','is_manager',
                    'created_at','last_login','team_leader','technical_support','supervisor','labeler',
                    'reviewer','approver','is_superuser')
    ## filter list
    list_filter = ('is_admin', 'organization','is_manager','is_verified','technical_support','supervisor','labeler',
                    'reviewer','approver',)
    ## admin page user create option
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password','fullName','is_verified',)}),
        ('Organizational info', {'fields': ('organization',)}),
        ('User Roles', {'fields': ('is_manager','is_admin','team_leader','technical_support','supervisor','labeler','reviewer','approver',)}),
        ('Django Permissions', {'fields': ('is_superuser',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'fullName','password1', 'password2','organization','is_verified','is_manager','is_admin',
                       'team_leader','technical_support','supervisor','labeler','reviewer','approver',),
        }),
    )
    ## search option
    search_fields = ('email',)
    ## order by
    ordering = ('email','created_at')
    filter_horizontal = ()

admin.site.register(User, UserModelAdmin)





class CustomOutstandingTokenAdmin(OutstandingTokenAdmin):
    list_display = (
        "id",
        "jti",
        "user",
        "created_at",
        "expires_at",
    )
admin.site.unregister(OutstandingToken)
admin.site.register(OutstandingToken, CustomOutstandingTokenAdmin)