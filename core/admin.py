"""Tenant-scoped admin inspection with narrow setup permissions.

The Django admin is an operator view, not an ingestion or response API. All
operational records are read-only here so writes retain their service/audit
boundaries. Staff membership is required in addition to Django staff access.
"""

from django.contrib import admin
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group

from .gmail_credentials import ADMIN_RESPONSE_SCOPE

from .models import (
    ActionExecution, AnalysisRun, Artifact, AuditEvent, EmailCase, Evidence,
    Feedback, Indicator, IndicatorSnapshot, InvestigationRun, InvestigationStep,
    Mailbox, Membership, Organization,
)


ALL_ROLES = tuple(Membership.Role.values)
MANAGER_ROLES = (Membership.Role.OWNER, Membership.Role.ADMIN)
INVESTIGATOR_ROLES = (*MANAGER_ROLES, Membership.Role.ANALYST)


class SuperuserOnlyAuthAdmin:
    """Keep Django's global user/group records outside tenant staff views."""

    def _allowed(self, request):
        return request.user.is_active and request.user.is_staff and request.user.is_superuser

    def has_module_permission(self, request):
        return self._allowed(request)

    def has_view_permission(self, request, obj=None):
        return self._allowed(request)

    def has_add_permission(self, request):
        return self._allowed(request)

    def has_change_permission(self, request, obj=None):
        return self._allowed(request)

    def has_delete_permission(self, request, obj=None):
        return self._allowed(request)


class RestrictedUserAdmin(SuperuserOnlyAuthAdmin, UserAdmin):
    pass


class RestrictedGroupAdmin(SuperuserOnlyAuthAdmin, GroupAdmin):
    pass


class ReadOnlySuperuserAdmin(SuperuserOnlyAuthAdmin, admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.unregister(get_user_model())
admin.site.register(get_user_model(), RestrictedUserAdmin)
admin.site.unregister(Group)
admin.site.register(Group, RestrictedGroupAdmin)


class TenantScopedAdmin(admin.ModelAdmin):
    visible_roles = ALL_ROLES
    organization_lookup = "organization_id"

    def _memberships(self, request, roles=None):
        return Membership.objects.filter(
            user=request.user,
            is_active=True,
            organization__is_active=True,
            role__in=roles or self.visible_roles,
        )

    def _can_view_any(self, request):
        return request.user.is_active and request.user.is_staff and (
            request.user.is_superuser or self._memberships(request).exists()
        )

    def _organization_id(self, obj):
        return obj.pk if isinstance(obj, Organization) else obj.organization_id

    def _has_role(self, request, organization_id, roles):
        if not request.user.is_active or not request.user.is_staff:
            return False
        if request.user.is_superuser:
            return True
        return self._memberships(request, roles).filter(organization_id=organization_id).exists()

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        if not request.user.is_active or not request.user.is_staff:
            return queryset.none()
        if request.user.is_superuser:
            return queryset
        organization_ids = self._memberships(request).values("organization_id")
        return queryset.filter(**{f"{self.organization_lookup}__in": organization_ids})

    def has_module_permission(self, request):
        return self._can_view_any(request)

    def has_view_permission(self, request, obj=None):
        if obj is None:
            return self._can_view_any(request)
        return self._has_role(request, self._organization_id(obj), self.visible_roles)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Organization)
class OrganizationAdmin(TenantScopedAdmin):
    class OrganizationForm(forms.ModelForm):
        class Meta:
            model = Organization
            fields = "__all__"

        def clean(self):
            values = super().clean()
            client_id = values.get("gmail_response_service_account_client_id", "")
            scope = values.get("gmail_response_scope", "")
            if bool(client_id) != bool(scope):
                raise forms.ValidationError("Response client ID and scope must be configured together.")
            if scope and scope != ADMIN_RESPONSE_SCOPE:
                raise forms.ValidationError("Administrator-delegated response requires gmail.modify.restricted.")
            if client_id and client_id == self.instance.gmail_service_account_client_id:
                raise forms.ValidationError("Response and ingestion must use separate service-account identities.")
            return values

    form = OrganizationForm
    visible_roles = MANAGER_ROLES
    organization_lookup = "pk"
    list_display = ("slug", "name", "is_active", "retention_days")
    search_fields = ("slug", "name")

    def has_add_permission(self, request):
        return request.user.is_active and request.user.is_staff and request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return obj is not None and self._has_role(request, obj.pk, (Membership.Role.OWNER,))

    def get_fields(self, request, obj=None):
        if obj is None:
            return ("name", "slug", "is_active", "retention_days")
        return ("id", "slug", "name", "is_active", "retention_days", "gmail_service_account_client_id", "gmail_access_verified_at", "gmail_response_service_account_client_id", "gmail_response_scope", "created_at", "updated_at")

    def get_readonly_fields(self, request, obj=None):
        return ("id", "slug", "gmail_service_account_client_id", "gmail_access_verified_at", "created_at", "updated_at") if obj else ()

@admin.register(Membership)
class MembershipAdmin(TenantScopedAdmin):
    visible_roles = MANAGER_ROLES
    list_display = ("organization", "user", "role", "is_active")
    list_select_related = ("organization", "user")

    def has_add_permission(self, request):
        return request.user.is_active and request.user.is_staff and request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return obj is not None and request.user.is_active and request.user.is_staff and request.user.is_superuser

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "organization" and not request.user.is_superuser:
            kwargs["queryset"] = Organization.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(Mailbox)
class MailboxAdmin(TenantScopedAdmin):
    list_display = ("address", "organization", "state", "gmail_sync_status", "gmail_last_synced_at", "sync_lag_seconds")
    list_select_related = ("organization",)
    search_fields = ("address", "display_name")

    @admin.display(description="Sync lag (seconds)")
    def sync_lag_seconds(self, obj):
        from django.utils import timezone
        return int((timezone.now() - obj.gmail_last_synced_at).total_seconds()) if obj.gmail_last_synced_at else None

    def has_add_permission(self, request):
        return request.user.is_active and request.user.is_staff and (
            request.user.is_superuser or self._memberships(request, MANAGER_ROLES).exists()
        )

    def has_change_permission(self, request, obj=None):
        return obj is not None and self._has_role(request, obj.organization_id, MANAGER_ROLES)

    def get_fields(self, request, obj=None):
        if obj is None:
            return ("organization", "address", "display_name")
        return (
            "organization", "address", "display_name", "state",
            "provider", "provider_mailbox_id", "gmail_sync_status", "gmail_enrolled_at", "gmail_enrollment_history_id", "gmail_history_id", "gmail_initial_sync_completed_at", "gmail_last_synced_at", "gmail_last_attempt_at", "gmail_next_sync_at", "gmail_retry_count", "gmail_coverage_gap_from_history_id", "gmail_coverage_gap_detected_at", "gmail_label_id", "last_error_code", "created_at", "updated_at",
            "investigation_sender_context_enabled", "investigation_conversation_enabled",
        )

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return ()
        return (
            "organization", "address", "state", "provider", "provider_mailbox_id", "gmail_sync_status", "gmail_enrolled_at", "gmail_enrollment_history_id", "gmail_history_id", "gmail_initial_sync_completed_at", "gmail_last_synced_at", "gmail_last_attempt_at", "gmail_next_sync_at", "gmail_retry_count", "gmail_coverage_gap_from_history_id", "gmail_coverage_gap_detected_at", "gmail_label_id",
            "last_error_code", "created_at", "updated_at",
        )

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "organization" and not request.user.is_superuser:
            allowed_ids = self._memberships(request, MANAGER_ROLES).values("organization_id")
            kwargs["queryset"] = Organization.objects.filter(pk__in=allowed_ids)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        if not self._has_role(request, obj.organization_id, MANAGER_ROLES):
            raise PermissionError("Mailbox organization is outside the user's management scope")
        super().save_model(request, obj, form, change)


@admin.register(EmailCase)
class EmailCaseAdmin(TenantScopedAdmin):
    list_display = ("id", "organization", "mailbox", "state", "verdict", "created_at")
    list_select_related = ("organization", "mailbox")
    list_filter = ("state", "verdict")


@admin.register(Artifact)
class ArtifactAdmin(TenantScopedAdmin):
    visible_roles = INVESTIGATOR_ROLES
    list_display = ("id", "organization", "case", "kind", "state", "size_bytes")
    list_select_related = ("organization", "case")
    exclude = ("file",)
    readonly_fields = ("private_storage_key",)

    @admin.display(description="Private storage key")
    def private_storage_key(self, obj):
        return obj.file.name or "No file stored"

    def get_fields(self, request, obj=None):
        return (
            "id", "organization", "case", "kind", "state", "private_storage_key",
            "original_filename", "content_type", "size_bytes", "sha256",
            "error_code", "created_at",
        )


@admin.register(AnalysisRun)
class AnalysisRunAdmin(TenantScopedAdmin):
    list_display = ("id", "organization", "case", "attempt", "state", "retry_count", "lease_expires_at", "error_code", "created_at")
    list_select_related = ("organization", "case")
    list_filter = ("state",)


@admin.register(IndicatorSnapshot)
class IndicatorSnapshotAdmin(ReadOnlySuperuserAdmin):
    list_display = ("source_name", "kind", "fetched_at", "expires_at", "is_active", "sha256")
    list_filter = ("kind", "is_active")


@admin.register(Indicator)
class IndicatorAdmin(ReadOnlySuperuserAdmin):
    list_display = ("indicator_type", "value", "snapshot")
    list_filter = ("indicator_type",)


@admin.register(Evidence)
class EvidenceAdmin(TenantScopedAdmin):
    list_display = ("id", "organization", "case", "source", "state", "observed_at")
    list_select_related = ("organization", "case")
    list_filter = ("source", "state", "trust")


@admin.register(InvestigationRun)
class InvestigationRunAdmin(TenantScopedAdmin):
    visible_roles = INVESTIGATOR_ROLES
    list_display = ("id", "organization", "mailbox", "case", "state", "stopping_reason", "calls_used")
    list_select_related = ("organization", "mailbox", "case")
    list_filter = ("state", "stopping_reason")


@admin.register(InvestigationStep)
class InvestigationStepAdmin(TenantScopedAdmin):
    visible_roles = INVESTIGATOR_ROLES
    organization_lookup = "investigation__organization_id"
    list_display = ("id", "investigation", "call_number", "tool_id", "state", "finished_at")
    list_select_related = ("investigation",)
    list_filter = ("tool_id", "state")

    def _organization_id(self, obj):
        return obj.investigation.organization_id


@admin.register(ActionExecution)
class ActionExecutionAdmin(TenantScopedAdmin):
    list_display = ("id", "organization", "case", "action", "state", "requested_at")
    list_select_related = ("organization", "case")
    list_filter = ("action", "state")


@admin.register(Feedback)
class FeedbackAdmin(TenantScopedAdmin):
    list_display = ("id", "organization", "case", "state", "proposed_verdict", "created_at")
    list_select_related = ("organization", "case")
    list_filter = ("state",)


@admin.register(AuditEvent)
class AuditEventAdmin(TenantScopedAdmin):
    visible_roles = INVESTIGATOR_ROLES
    list_display = ("id", "organization", "case", "event_type", "occurred_at")
    list_select_related = ("organization", "case")
    list_filter = ("event_type",)
