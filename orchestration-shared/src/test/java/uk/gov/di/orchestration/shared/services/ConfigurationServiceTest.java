package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

import java.net.URI;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConfigurationServiceTest {

    private final SystemService systemService = mock(SystemService.class);

    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(3600, configurationService.getSessionCookieMaxAge());
    }

    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }

    @Test
    void shouldReadTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("1.1,1.3,1.5");

        ConfigurationService configurationService = new ConfigurationService();
        configurationService.setSystemService(systemService);

        assertEquals(
                List.of("1.1", "1.3", "1.5"),
                configurationService.getBulkUserEmailIncludedTermsAndConditions());
    }

    @Test
    void shouldReadEmptyTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("");

        ConfigurationService configurationService = new ConfigurationService();
        configurationService.setSystemService(systemService);

        assertEquals(
                Collections.EMPTY_LIST,
                configurationService.getBulkUserEmailIncludedTermsAndConditions());
    }

    @Test
    void shoulCacheTheNotifyBearerTokenAfterTheFirstCall() {
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

    @Test
    void shouldHandleMissingAISUrl() {
        when(systemService.getOrDefault("ACCOUNT_INTERVENTION_SERVICE_URI", "")).thenReturn("");

        ConfigurationService configurationService = new ConfigurationService();
        configurationService.setSystemService(systemService);

        assertEquals(configurationService.getAccountInterventionServiceURI(), URI.create(""));
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
