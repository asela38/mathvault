from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = BaseUserAdmin.list_display + ("password_compromised_at",)
    fieldsets = BaseUserAdmin.fieldsets + (("Security", {"fields": ("password_compromised_at",)}),)
    actions = ["mark_compromised"]

    @admin.action(description="Mark password as compromised (forces a change at next request)")
    def mark_compromised(self, request, queryset):
        for user in queryset:
            user.mark_password_compromised()
