package uk.gov.di.authentication.auditevents.entity.shared;

import uk.gov.di.audit.AuditContext;

public record RestrictedDeviceInformation(EncodedDeviceInformation deviceInformation) {
    public static RestrictedDeviceInformation from(AuditContext auditContext) {
        return new RestrictedDeviceInformation(EncodedDeviceInformation.from(auditContext));
    }
}
