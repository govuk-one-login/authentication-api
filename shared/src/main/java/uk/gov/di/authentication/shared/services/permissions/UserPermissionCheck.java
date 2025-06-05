package uk.gov.di.authentication.shared.services.permissions;

public record UserPermissionCheck(
        UserPermissionStatus status, UserPermissionCheckContext context) {}
