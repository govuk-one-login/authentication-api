package uk.gov.di.accountmanagement.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthenticatorItemKeyTest {

    @Test
    void shouldSetAndGetPublicSubjectId() {
        var item = new AuthenticatorItemKey();
        item.setPublicSubjectId("test-public-subject-id");
        assertEquals("test-public-subject-id", item.getPublicSubjectId());
    }

    @Test
    void shouldSetAndGetSortKey() {
        var item = new AuthenticatorItemKey();
        item.setSortKey("PASSKEY#credential-123");
        assertEquals("PASSKEY#credential-123", item.getSortKey());
    }

    @Test
    void shouldReturnNullWhenFieldsNotSet() {
        var item = new AuthenticatorItemKey();
        assertNull(item.getPublicSubjectId());
        assertNull(item.getSortKey());
    }
}
