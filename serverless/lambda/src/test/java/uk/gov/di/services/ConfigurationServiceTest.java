package uk.gov.di.services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurationServiceTest {

    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(1800, configurationService.getSessionCookieMaxAge());
    }

    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }
}
