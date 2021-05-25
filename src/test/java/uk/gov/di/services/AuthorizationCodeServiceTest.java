package uk.gov.di.services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationCodeServiceTest {

    private static AuthorizationCodeService authorizationCodeService =
            new AuthorizationCodeService();

    @Test
    void shouldIssueAndStoreCodeForUser() {
        var code = authorizationCodeService.issueCodeForUser("user@example.com");

        assertEquals("user@example.com", authorizationCodeService.getEmailForCode(code).get());
    }

    @Test
    void shouldOnlyAllowRetrievalOfCodeOnce() {
        var code = authorizationCodeService.issueCodeForUser("user@example.com");

        assertEquals("user@example.com", authorizationCodeService.getEmailForCode(code).get());
        assertTrue(authorizationCodeService.getEmailForCode(code).isEmpty());
    }
}
