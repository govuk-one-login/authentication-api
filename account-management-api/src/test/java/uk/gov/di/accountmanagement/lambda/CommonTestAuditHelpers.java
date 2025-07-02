package uk.gov.di.accountmanagement.lambda;

import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.services.AuditService;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CommonTestAuditHelpers {
    public static void containsMetadataPair(
            AuditContext capturedObject, String field, String value) {
        capturedObject
                .getMetadataItemByKey(field)
                .ifPresent(
                        actualMetadataPairForMfaMethod ->
                                assertEquals(
                                        AuditService.MetadataPair.pair(field, value),
                                        actualMetadataPairForMfaMethod));
    }
}
