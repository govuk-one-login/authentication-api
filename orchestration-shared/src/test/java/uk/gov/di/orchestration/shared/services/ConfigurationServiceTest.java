package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

import java.net.URI;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class ConfigurationServiceTest {

    private final SystemService systemService = mock(SystemService.class);

    // QualityGateRegressionTest
    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(3600, configurationService.getSessionCookieMaxAge());
    }

    // QualityGateRegressionTest
    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }

    // QualityGateRegressionTest
    @Test
    void shouldReadTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("1.1,1.3,1.5");

        ConfigurationService configurationService = new ConfigurationService(systemService);

        assertEquals(
                List.of("1.1", "1.3", "1.5"),
                configurationService.getBulkUserEmailIncludedTermsAndConditions());
    }

    // QualityGateRegressionTest
    @Test
    void shouldReadEmptyTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("");

        ConfigurationService configurationService = new ConfigurationService(systemService);

        assertEquals(
                Collections.EMPTY_LIST,
                configurationService.getBulkUserEmailIncludedTermsAndConditions());
    }

    // QualityGateRegressionTest
    @Test
    void shouldCacheTheNotifyBearerTokenAfterTheFirstCall() {
        var mock = mock(SsmClient.class);
        ConfigurationService configurationService = new ConfigurationService(mock);

        String ssmParamName = "test-notify-callback-bearer-token";
        String ssmParamValue = "bearer-token";

        var request = parameterRequest(ssmParamName);
        var response = parameterResponse(ssmParamName, ssmParamValue);

        when(mock.getParameter(parameterRequest(ssmParamName))).thenReturn(response);

        assertEquals(configurationService.getNotifyCallbackBearerToken(), ssmParamValue);
        assertEquals(configurationService.getNotifyCallbackBearerToken(), ssmParamValue);
        verify(mock, times(1)).getParameter(request);
    }

    // QualityGateRegressionTest
    @Test
    void shouldHandleMissingAISUrl() {
        when(systemService.getOrDefault("ACCOUNT_INTERVENTION_SERVICE_URI", "")).thenReturn("");

        ConfigurationService configurationService = new ConfigurationService(systemService);

        assertEquals(configurationService.getAccountInterventionServiceURI(), URI.create(""));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowUncheckedExceptionIfUrlNotValid() {
        when(systemService.getOrDefault("IPV_JWKS_URL", ""))
                .thenReturn("not-a-protocol://test.com");

        ConfigurationService configurationService = new ConfigurationService(systemService);

        assertThrows(RuntimeException.class, configurationService::getIPVJwksUrl);
    }

    private GetParameterRequest parameterRequest(String name) {
        return GetParameterRequest.builder().withDecryption(true).name(name).build();
    }

    private GetParameterResponse parameterResponse(String name, String value) {
        return GetParameterResponse.builder()
                .parameter(
                        software.amazon.awssdk.services.ssm.model.Parameter.builder()
                                .name(name)
                                .type("String")
                                .value(value)
                                .build())
                .build();
    }
}
