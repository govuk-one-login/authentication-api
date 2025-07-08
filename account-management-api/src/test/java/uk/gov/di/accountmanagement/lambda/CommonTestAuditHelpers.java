package uk.gov.di.accountmanagement.lambda;

import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.services.AuditService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CommonTestAuditHelpers {
    public static void containsMetadataPair(
            AuditContext capturedObject, String field, String value) {
        capturedObject
                .getMetadataItemByKey(field)
                .ifPresentOrElse(
                        actualMetadataPairForMfaMethod ->
                                assertEquals(
                                        AuditService.MetadataPair.pair(field, value),
                                        actualMetadataPairForMfaMethod),
                        () -> fail("Missing metadata key: " + field));
    }
}
