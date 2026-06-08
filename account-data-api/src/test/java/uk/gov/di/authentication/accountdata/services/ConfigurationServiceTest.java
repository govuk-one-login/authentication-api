package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SystemStubsExtension.class)
class ConfigurationServiceTest {

    private static final ConfigurationService configurationService = new ConfigurationService();

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @Test
    void getAwsRegionShouldNotDefault() {
        environment.set("AWS_REGION", null);
        assertEquals(null, configurationService.getAwsRegion());
    }

    @Test
    void getEnvironmentShouldDefaultToTest() {
        environment.set("ENVIRONMENT", null);
        assertEquals("test", configurationService.getEnvironment());
    }

    @Test
    void getDynamoArnPrefixShouldReturnEmptyOptionalByDefault() {
        environment.set("DYNAMO_ARN_PREFIX", null);
        assertFalse(configurationService.getDynamoArnPrefix().isPresent());
    }

    @Test
    void getDynamoEndpointUriShouldReturnEmptyOptionalByDefault() {
        environment.set("DYNAMO_ENDPOINT", null);
        assertFalse(configurationService.getDynamoEndpointUri().isPresent());
    }

    @Test
    void getAccountDataJwksUrlShouldThrowMalformedUrlExceptionWhenUrlIsNull() {
        environment.set("ACCOUNT_DATA_JWKS_URL", null);
        assertThrows(MalformedURLException.class, configurationService::getAccountDataJwksUrl);
    }

    @Test
    void getAuthIssuerClaimShouldDefaultToEmptyString() {
        environment.set("AUTH_ISSUER_CLAIM", null);
        assertEquals("", configurationService.getAuthIssuerClaim());
    }

    @Test
    void getAMCClientIdShouldDefaultToEmptyString() {
        environment.set("AMC_CLIENT_ID", null);
        assertEquals("", configurationService.getAMCClientId());
    }

    @Test
    void getHomeClientIdShouldDefaultToEmptyString() {
        environment.set("HOME_CLIENT_ID", null);
        assertEquals("", configurationService.getHomeClientId());
    }

    @Test
    void getAuthToAccountDataApiAudienceShouldDefaultToEmptyString() {
        environment.set("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE", null);
        assertEquals("", configurationService.getAuthToAccountDataApiAudience());
    }
}
