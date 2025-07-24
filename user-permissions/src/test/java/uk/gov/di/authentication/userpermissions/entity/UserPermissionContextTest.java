package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
        assertEquals(INTERNAL_SUBJECT_ID, context.internalSubjectId());
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
        assertEquals(null, context.internalSubjectId());
        assertEquals(null, context.rpPairwiseId());
        assertEquals(null, context.emailAddress());
        assertEquals(null, context.authSessionItem());
    }
}
