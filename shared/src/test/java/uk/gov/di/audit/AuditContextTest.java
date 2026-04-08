package uk.gov.di.audit;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

class AuditContextTest {

    @Test
    void shouldMaintainImmutabilityWhenAddingMetadataItem() {
        // Given
        List<AuditService.MetadataPair> originalMetadata = new ArrayList<>();
        AuditContext auditContext =
                new AuditContext(
                        "client-id",
                        "client-session-id",
                        "session-id",
                        "subject-id",
                        "email@example.com",
                        "127.0.0.1",
                        "+447700900000",
                        "persistent-session-id",
                        Optional.empty(),
                        originalMetadata);

        // When
        AuditService.MetadataPair metadataPair = AuditService.MetadataPair.pair("key1", "value1");
        AuditContext updatedContext = auditContext.withMetadataItem(metadataPair);

        // Then
        // Original metadata list should be empty
        assertTrue(originalMetadata.isEmpty());
        // Original context's metadata should be empty
        assertTrue(auditContext.metadata().isEmpty());
        // Updated context should have one item
        assertEquals(1, updatedContext.metadata().size());
        // The lists should be different objects
        assertNotSame(auditContext.metadata(), updatedContext.metadata());
    }

    @Test
    void shouldAddMetadataItemsCorrectly() {
        // Given
        AuditContext auditContext =
                new AuditContext(
                        "client-id",
                        "client-session-id",
                        "session-id",
                        "subject-id",
                        "email",
                        "ip-address",
                        "phone-number",
                        "persistent-session-id",
                        Optional.empty(),
                        new ArrayList<>());

        // When
        auditContext = auditContext.withMetadataItem(pair("key1", "value1", false));
        auditContext = auditContext.withMetadataItem(pair("key2", "value2", false));

        // Then
        assertEquals(2, auditContext.metadata().size());
        Optional<AuditService.MetadataPair> key1Pair = auditContext.getMetadataItemByKey("key1");
        Optional<AuditService.MetadataPair> key2Pair = auditContext.getMetadataItemByKey("key2");

        assertTrue(key1Pair.isPresent());
        assertTrue(key2Pair.isPresent());
        assertEquals("value1", key1Pair.get().value());
        assertEquals("value2", key2Pair.get().value());
    }

    @Test
    void shouldHandleNullMetadataItem() {
        // Given
        AuditContext auditContext = AuditContext.emptyAuditContext();

        // When
        AuditContext updatedContext = auditContext.withMetadataItem(null);

        // Then
        // Should return the same instance when null is provided
        assertEquals(auditContext, updatedContext);
    }

    @Test
    void shouldCreateNewInstanceForEachWithMethod() {
        // Given
        AuditContext original = AuditContext.emptyAuditContext();

        // When
        AuditContext withNewEmail = original.withEmail("new@example.com");
        AuditContext withNewPhone = original.withPhoneNumber("+447700900001");
        AuditContext withNewSubjectId = original.withSubjectId("new-subject-id");

        // Then
        assertNotSame(original, withNewEmail);
        assertNotSame(original, withNewPhone);
        assertNotSame(original, withNewSubjectId);
        assertEquals("new@example.com", withNewEmail.email());
        assertEquals("+447700900001", withNewPhone.phoneNumber());
        assertEquals("new-subject-id", withNewSubjectId.subjectId());
    }

    @Test
    void shouldNotModifyOriginalMetadataWhenAddingMultipleItems() {
        // Given
        AuditContext original = AuditContext.emptyAuditContext();

        // When
        AuditContext withFirstItem =
                original.withMetadataItem(AuditService.MetadataPair.pair("key1", "value1"));
        AuditContext withSecondItem =
                withFirstItem.withMetadataItem(AuditService.MetadataPair.pair("key2", "value2"));

        // Then
        assertTrue(original.metadata().isEmpty());
        assertEquals(1, withFirstItem.metadata().size());
        assertEquals(2, withSecondItem.metadata().size());

        // Verify the first context still only has the first item
        assertEquals("key1", withFirstItem.metadata().get(0).key());
        assertEquals("value1", withFirstItem.metadata().get(0).value());

        // Verify the second context has both items
        assertEquals("key1", withSecondItem.metadata().get(0).key());
        assertEquals("value1", withSecondItem.metadata().get(0).value());
        assertEquals("key2", withSecondItem.metadata().get(1).key());
        assertEquals("value2", withSecondItem.metadata().get(1).value());
    }
}
