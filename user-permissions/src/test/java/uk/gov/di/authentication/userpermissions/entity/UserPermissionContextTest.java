package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserPermissionContextTest {

    private static final String INTERNAL_SUBJECT_ID = "test-internal-subject-id";
    private static final String RP_PAIRWISE_ID = "test-rp-pairwise-id";
    private static final String EMAIL_ADDRESS = "test@example.com";

    @Test
    void shouldBuildUserPermissionContextSuccessfully() {
        // Given
        AuthSessionItem authSessionItem = new AuthSessionItem();
        authSessionItem.setSessionId("test-session-id");

        // When
        UserPermissionContext context =
                UserPermissionContext.builder()
                        .withInternalSubjectId(INTERNAL_SUBJECT_ID)
                        .withRpPairwiseId(RP_PAIRWISE_ID)
                        .withEmailAddress(EMAIL_ADDRESS)
                        .withAuthSessionItem(authSessionItem)
                        .build();

        // Then
        assertEquals(List.of(INTERNAL_SUBJECT_ID), context.internalSubjectIds());
        assertEquals(RP_PAIRWISE_ID, context.rpPairwiseId());
        assertEquals(EMAIL_ADDRESS, context.emailAddress());
        assertNotNull(context.authSessionItem());
        assertEquals("test-session-id", context.authSessionItem().getSessionId());
    }

    @Test
    void shouldBuildUserPermissionContextWithNullValues() {
        // When
        UserPermissionContext context = UserPermissionContext.builder().build();

        // Then
        assertEquals(null, context.internalSubjectIds());
        assertEquals(null, context.rpPairwiseId());
        assertEquals(null, context.emailAddress());
        assertEquals(null, context.authSessionItem());
    }

    @Test
    void shouldBuildUserPermissionContextWithNullInternalSubjectIdInBuilder() {
        // When
        UserPermissionContext context =
                UserPermissionContext.builder()
                        .withInternalSubjectId(null)
                        .withRpPairwiseId(RP_PAIRWISE_ID)
                        .withEmailAddress(EMAIL_ADDRESS)
                        .build();

        // Then
        assertEquals(List.of(), context.internalSubjectIds());
        assertNull(context.internalSubjectId());
        assertEquals(RP_PAIRWISE_ID, context.rpPairwiseId());
        assertEquals(EMAIL_ADDRESS, context.emailAddress());
    }

    @Test
    void shouldReturnSingleInternalSubjectIdSuccessfully() {
        // When
        UserPermissionContext context =
                UserPermissionContext.builder().withInternalSubjectId(INTERNAL_SUBJECT_ID).build();

        // Then
        assertEquals(List.of(INTERNAL_SUBJECT_ID), context.internalSubjectIds());
        assertEquals(INTERNAL_SUBJECT_ID, context.internalSubjectId());
    }

    @Test
    void shouldThrowExceptionWhenAccessingSingleInternalSubjectIdWhenThereAreMultipleIds() {
        // Given
        UserPermissionContext context =
                UserPermissionContext.builder()
                        .withInternalSubjectIds(List.of("id1", "id2"))
                        .build();

        // When/Then
        IllegalStateException exception =
                assertThrows(IllegalStateException.class, context::internalSubjectId);
        assertEquals(
                "Cannot get single internalSubjectId when multiple IDs exist",
                exception.getMessage());
    }
}
