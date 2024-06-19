package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
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

    @Test
    void getAccountCreationLockoutCountTTLShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(3600, configurationService.getAccountCreationLockoutCountTTL());
    }

    @Test
    void supportAccountCreationTTLShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(false, configurationService.supportAccountCreationTTL());
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

    @Test
    void shouldGetNotificationTypeFromTemplateId() {
        when(systemService.getenv("VERIFY_EMAIL_TEMPLATE_ID")).thenReturn("1234-abcd");
        when(systemService.getenv("EMAIL_UPDATED_TEMPLATE_ID")).thenReturn("1234-efgh,4567-ijkl");
        when(systemService.getenv("TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID"))
                .thenReturn("1234-bulk");
        when(systemService.getenv("REPORT_SUSPICIOUS_ACTIVITY_EMAIL_TEMPLATE_ID"))
                .thenReturn("report-template-id");

        ConfigurationService configurationService = new ConfigurationService();
        configurationService.setSystemService(systemService);

        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.VERIFY_EMAIL),
                configurationService.getNotificationTypeFromTemplateId("1234-abcd"));
        assertEquals(
                Optional.empty(),
                configurationService.getNotificationTypeFromTemplateId("1234-wxyz"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.EMAIL_UPDATED),
                configurationService.getNotificationTypeFromTemplateId("4567-ijkl"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.EMAIL_UPDATED),
                configurationService.getNotificationTypeFromTemplateId("1234-efgh"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL),
                configurationService.getNotificationTypeFromTemplateId("1234-bulk"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.REPORT_SUSPICIOUS_ACTIVITY),
                configurationService.getNotificationTypeFromTemplateId("report-template-id"));
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
