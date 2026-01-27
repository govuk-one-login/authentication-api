package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionContextTest {

    private static final String INTERNAL_SUBJECT_ID = "test-internal-subject-id";
    private static final String RP_PAIRWISE_ID = "test-rp-pairwise-id";
    private static final String EMAIL_ADDRESS = "test@example.com";
    private static final String E164_FORMATTED_PHONE_NUMBER = "+447234567890";

    @Test
    void shouldBuildPermissionContextSuccessfully() {
        // Given
        AuthSessionItem authSessionItem = new AuthSessionItem();
        authSessionItem.setSessionId("test-session-id");

        // When
        PermissionContext context =
                PermissionContext.builder()
                        .withInternalSubjectId(INTERNAL_SUBJECT_ID)
                        .withRpPairwiseId(RP_PAIRWISE_ID)
                        .withEmailAddress(EMAIL_ADDRESS)
                        .withAuthSessionItem(authSessionItem)
                        .withE164FormattedPhoneNumber(E164_FORMATTED_PHONE_NUMBER)
                        .build();

        // Then
        assertEquals(List.of(INTERNAL_SUBJECT_ID), context.internalSubjectIds());
        assertEquals(RP_PAIRWISE_ID, context.rpPairwiseId());
        assertEquals(EMAIL_ADDRESS, context.emailAddress());
        assertNotNull(context.authSessionItem());
        assertEquals("test-session-id", context.authSessionItem().getSessionId());
        assertEquals(Optional.of(E164_FORMATTED_PHONE_NUMBER), context.e164FormattedPhoneNumber());
    }

    @Test
    void shouldBuildPermissionContextWithNullValues() {
        // When
        PermissionContext context = PermissionContext.builder().build();

        // Then
        assertEquals(null, context.internalSubjectIds());
        assertEquals(null, context.rpPairwiseId());
        assertEquals(null, context.emailAddress());
        assertEquals(null, context.authSessionItem());
        assertEquals(null, context.e164FormattedPhoneNumber());
    }

    @Test
    void shouldBuildPermissionContextWithNullInternalSubjectIdInBuilder() {
        // When
        PermissionContext context =
                PermissionContext.builder()
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
        PermissionContext context =
                PermissionContext.builder().withInternalSubjectId(INTERNAL_SUBJECT_ID).build();

        // Then
        assertEquals(List.of(INTERNAL_SUBJECT_ID), context.internalSubjectIds());
        assertEquals(INTERNAL_SUBJECT_ID, context.internalSubjectId());
    }

    @Test
    void shouldThrowExceptionWhenAccessingSingleInternalSubjectIdWhenThereAreMultipleIds() {
        // Given
        PermissionContext context =
                PermissionContext.builder().withInternalSubjectIds(List.of("id1", "id2")).build();

        // When/Then
        IllegalStateException exception =
                assertThrows(IllegalStateException.class, context::internalSubjectId);
        assertEquals(
                "Cannot get single internalSubjectId when multiple IDs exist",
                exception.getMessage());
    }

    @Test
    void shouldBuildPermissionContextWithNullPhoneNumber() {
        // When
        PermissionContext context =
                PermissionContext.builder()
                        .withInternalSubjectId(INTERNAL_SUBJECT_ID)
                        .withEmailAddress(EMAIL_ADDRESS)
                        .withE164FormattedPhoneNumber(null)
                        .build();

        // Then
        assertNotNull(context.e164FormattedPhoneNumber());
        assertTrue(context.e164FormattedPhoneNumber().isEmpty());
    }

    @Test
    void shouldBuildPermissionContextFromExistingContext() {
        // Given
        AuthSessionItem authSessionItem = new AuthSessionItem();
        authSessionItem.setSessionId("test-session-id");
        PermissionContext original =
                PermissionContext.builder()
                        .withInternalSubjectId(INTERNAL_SUBJECT_ID)
                        .withRpPairwiseId(RP_PAIRWISE_ID)
                        .withEmailAddress(EMAIL_ADDRESS)
                        .withAuthSessionItem(authSessionItem)
                        .withE164FormattedPhoneNumber(E164_FORMATTED_PHONE_NUMBER)
                        .build();

        // When
        PermissionContext copy = PermissionContext.builder().from(original).build();

        // Then
        assertEquals(original.internalSubjectIds(), copy.internalSubjectIds());
        assertEquals(original.rpPairwiseId(), copy.rpPairwiseId());
        assertEquals(original.emailAddress(), copy.emailAddress());
        assertEquals(original.authSessionItem(), copy.authSessionItem());
        assertEquals(original.e164FormattedPhoneNumber(), copy.e164FormattedPhoneNumber());
    }
}
