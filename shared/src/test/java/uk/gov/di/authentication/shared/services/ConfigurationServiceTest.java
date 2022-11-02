package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigurationServiceTest {

    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(7200, configurationService.getSessionCookieMaxAge());
    }

    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }

    private static Stream<Arguments> commaSeparatedStringContains() {
        return Stream.of(
                Arguments.of("1234", null, false),
                Arguments.of("1234", "", false),
                Arguments.of("", "", false),
                Arguments.of(null, "1234", false),
                Arguments.of("1234", "1234", true),
                Arguments.of("1234", "1234,4567", true),
                Arguments.of("4567", "1234,4567", true),
                Arguments.of("8901", "1234,4567,8901", true),
                Arguments.of(
                        "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9",
                        "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9",
                        true),
                Arguments.of(
                        "cc30aac4-4aae-4706-b147-9df40bd2feb8",
                        "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9,cc30aac4-4aae-4706-b147-9df40bd2feb8",
                        true),
                Arguments.of(
                        "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9",
                        "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9,cc30aac4-4aae-4706-b147-9df40bd2feb8",
                        true));
    }

    @ParameterizedTest
    @MethodSource("commaSeparatedStringContains")
    void shouldCheckCommaSeparatedStringContains(
            String searchTerm, String searchString, boolean result) {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(
                result, configurationService.commaSeparatedListContains(searchTerm, searchString));
    }
}
