package uk.gov.di.authentication.auditevents.entity.shared;

import uk.gov.di.audit.AuditContext;

public record EncodedDeviceInformation(String encoded) {
    public static EncodedDeviceInformation from(AuditContext auditContext) {
        return new EncodedDeviceInformation(auditContext.txmaAuditEncoded());
    }
}
