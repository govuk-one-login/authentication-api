package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

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
