package uk.gov.di.accountmanagement.lambda;

import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CommonTestAuditHelpers {
    public static void containsMetadataPair(
            AuditContext capturedObject, String field, String value) {
        Optional<AuditService.MetadataPair> metadataItem =
                capturedObject.getMetadataItemByKey(field);
        assertTrue(
                metadataItem.isPresent(),
                "Metadata field '" + field + "' not found in audit context");
        assertEquals(
                AuditService.MetadataPair.pair(field, value),
                metadataItem.get(),
                "Metadata field '" + field + "' has incorrect value");
    }
}
