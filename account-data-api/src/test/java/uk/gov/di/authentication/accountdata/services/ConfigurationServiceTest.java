package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfigurationServiceTest {

    private static final ConfigurationService configurationService = new ConfigurationService();

    @Test
    void getAwsRegionShouldNotDefault() {
        assertEquals(null, configurationService.getAwsRegion());
    }

    @Test
    void getEnvironmentShouldDefaultToTest() {
        assertEquals("test", configurationService.getEnvironment());
    }

    @Test
    void getDynamoArnPrefixShouldReturnEmptyOptionalByDefault() {
        assertFalse(configurationService.getDynamoArnPrefix().isPresent());
    }

    @Test
    void getDynamoEndpointUriShouldReturnEmptyOptionalByDefault() {
        assertFalse(configurationService.getDynamoEndpointUri().isPresent());
    }

    @Test
    void getAccountDataJwksUrlShouldThrowMalformedUrlExceptionWhenUrlIsNull() {
        assertThrows(MalformedURLException.class, configurationService::getAccountDataJwksUrl);
    }

    @Test
    void getAuthIssuerClaimShouldDefaultToEmptyString() {
        assertEquals("", configurationService.getAuthIssuerClaim());
    }

    @Test
    void getAMCClientIdShouldDefaultToEmptyString() {
        assertEquals("", configurationService.getAMCClientId());
    }

    @Test
    void getHomeClientIdShouldDefaultToEmptyString() {
        assertEquals("", configurationService.getHomeClientId());
    }

    @Test
    void getAuthToAccountDataApiAudienceShouldDefaultToEmptyString() {
        assertEquals("", configurationService.getAuthToAccountDataApiAudience());
    }
}
