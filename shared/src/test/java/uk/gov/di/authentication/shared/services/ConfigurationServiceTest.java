package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConfigurationServiceTest {
    private static ConfigurationService configurationService;
    private final SystemService systemService = mock(SystemService.class);

    @BeforeAll
    static void beforeAll() {
        configurationService = ConfigurationService.getInstance();
    }

    @Test
    void checkIsSingleton() {
        var configurationServiceInstance = ConfigurationService.getInstance();
        assertEquals(configurationService, configurationServiceInstance);
    }

    @Test
    void getAccessTokenExpiryShouldDefault() {
        assertEquals(180, configurationService.getAccessTokenExpiry());
    }

    @Test
    void getAccountManagementURIShouldDefault() {
        assertNull(configurationService.getAccountManagementURI());
    }

    @Test
    void getAuthCodeExpiryShouldDefault() {
        assertEquals(300, configurationService.getAuthCodeExpiry());
    }

    @Test
    void getIncorrectPasswordLockoutCountTTLShouldDefault() {
        assertEquals(900, configurationService.getIncorrectPasswordLockoutCountTTL());
    }

    @Test
    void getLockoutCountTTLShouldDefault() {
        assertEquals(900, configurationService.getLockoutCountTTL());
    }

    @Test
    void getReauthEnterEmailCountTTLShouldDefault() {
        assertEquals(3600, configurationService.getReauthEnterEmailCountTTL());
    }

    @Test
    void getLockoutDurationShouldDefault() {
        assertEquals(900, configurationService.getLockoutDuration());
    }

    @Test
    void getBulkUserEmailBatchQueryLimitShouldDefault() {
        assertEquals(25, configurationService.getBulkUserEmailBatchQueryLimit());
    }

    @Test
    void getBulkUserEmailMaxBatchCountShouldDefault() {
        assertEquals(20, configurationService.getBulkUserEmailMaxBatchCount());
    }

    @Test
    void getBulkUserEmailMaxAudienceLoadUserCountShouldDefault() {
        assertEquals(0, configurationService.getBulkUserEmailMaxAudienceLoadUserCount());
    }

    @Test
    void getBulkUserEmailAudienceLoadUserBatchSizeShouldDefault() {
        assertEquals(0, configurationService.getBulkUserEmailAudienceLoadUserBatchSize());
    }

    @Test
    void getBulkUserEmailBatchPauseDurationShouldDefault() {
        assertEquals(0, configurationService.getBulkUserEmailBatchPauseDuration());
    }

    @Test
    void shouldReadTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("1.1,1.3,1.5");

        ConfigurationService configurationServiceWithMockedSystemService =
                new ConfigurationService();
        configurationServiceWithMockedSystemService.setSystemService(systemService);

        assertEquals(
                List.of("1.1", "1.3", "1.5"),
                configurationServiceWithMockedSystemService
                        .getBulkUserEmailIncludedTermsAndConditions());
    }

    @Test
    void shouldReadEmptyTermsAndConditionsVersionCSVList() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", ""))
                .thenReturn("");

        ConfigurationService configurationServiceWithMockedSystemService =
                new ConfigurationService();
        configurationServiceWithMockedSystemService.setSystemService(systemService);

        assertEquals(
                Collections.EMPTY_LIST,
                configurationServiceWithMockedSystemService
                        .getBulkUserEmailIncludedTermsAndConditions());
    }

    @Test
    void getBulkEmailUserSendModeShouldDefault() {
        when(systemService.getOrDefault("BULK_USER_EMAIL_SEND_MODE", "PENDING"))
                .thenReturn("1.1,1.3,1.5");

        ConfigurationService configurationServiceWithMockedSystemService =
                new ConfigurationService();
        configurationServiceWithMockedSystemService.setSystemService(systemService);

        assertEquals(
                "1.1,1.3,1.5",
                configurationServiceWithMockedSystemService.getBulkEmailUserSendMode());
    }

    @Test
    void isBulkUserEmailEnabledShouldDefault() {
        assertFalse(configurationService.isBulkUserEmailEnabled());
    }

    @Test
    void getDefaultOtpCodeExpiryShouldDefault() {
        assertEquals(900, configurationService.getDefaultOtpCodeExpiry());
    }

    @Test
    void getEmailAccountCreationOtpCodeExpiryShouldDefault() {
        assertEquals(3600, configurationService.getEmailAccountCreationOtpCodeExpiry());
    }

    @Test
    void getCodeMaxRetriesShouldDefault() {
        assertEquals(6, configurationService.getCodeMaxRetries());
    }

    @Test
    void getIncreasedCodeMaxRetriesShouldDefault() {
        assertEquals(999999, configurationService.getIncreasedCodeMaxRetries());
    }

    @Test
    void getAuthAppCodeWindowLengthShouldDefault() {
        assertEquals(30, configurationService.getAuthAppCodeWindowLength());
    }

    @Test
    void getAuthAppCodeAllowedWindowsShouldDefault() {
        assertEquals(9, configurationService.getAuthAppCodeAllowedWindows());
    }

    @Test
    void isEmailCheckEnabledShouldDefault() {
        assertFalse(configurationService.isEmailCheckEnabled());
    }

    @Test
    void isBulkUserEmailEmailSendingEnabledShouldDefault() {
        assertFalse(configurationService.isBulkUserEmailEmailSendingEnabled());
    }

    @Test
    void getBulkEmailLoaderLambdaNameShouldDefault() {
        assertEquals("", configurationService.getBulkEmailLoaderLambdaName());
    }

    @Test
    void getTicfCRILambdaNameShouldDefault() {
        assertEquals("", configurationService.getTicfCRILambdaIdentifier());
    }

    @Test
    void isInvokeTicfCRILambdaEnabledShouldDefault() {
        assertFalse(configurationService.isInvokeTicfCRILambdaEnabled());
    }

    @Test
    void getAuthenticationAuthCallbackURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getAuthenticationAuthCallbackURI());
    }

    @Test
    void getAuthenticationBackendURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getAuthenticationBackendURI());
    }

    @Test
    void getOrchestrationBackendURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getOrchestrationBackendURI());
    }

    @Test
    void getContactUsLinkRouteShouldDefault() {
        assertEquals("", configurationService.getContactUsLinkRoute());
    }

    @Test
    void getMaxPasswordRetriesShouldDefault() {
        assertEquals(6, configurationService.getMaxPasswordRetries());
    }

    @Test
    void getMaxEmailReAuthRetriesShouldDefault() {
        assertEquals(6, configurationService.getMaxEmailReAuthRetries());
    }

    @Test
    void isCustomDocAppClaimEnabledShouldDefault() {
        assertFalse(configurationService.isCustomDocAppClaimEnabled());
    }

    @Test
    void getDocAppAuthorisationURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getDocAppAuthorisationURI());
    }

    @Test
    void getDocAppAuthorisationCallbackURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getDocAppAuthorisationCallbackURI());
    }

    @Test
    void getDocAppAuthorisationClientIdShouldDefault() {
        assertEquals("", configurationService.getDocAppAuthorisationClientId());
    }

    @Test
    void getDocAppJwksUriShouldDefault() {
        assertEquals(URI.create(""), configurationService.getDocAppJwksUri());
    }

    @Test
    void getDocAppTokenSigningKeyAliasShouldNotDefault() {
        assertNull(configurationService.getDocAppTokenSigningKeyAlias());
    }

    @Test
    void getDynamoArnPrefixShouldDefault() {
        assertFalse(configurationService.getDynamoArnPrefix().isPresent());
    }

    @Test
    void getDynamoEndpointUriShouldDefault() {
        assertFalse(configurationService.getDynamoEndpointUri().isPresent());
    }

    @Test
    void getEmailQueueUriShouldNotDefault() {
        assertNull(configurationService.getEmailQueueUri());
    }

    @Test
    void getPendingEmailCheckQueueUriShouldNotDefault() {
        assertNull(configurationService.getPendingEmailCheckQueueUri());
    }

    @Test
    void getExperianPhoneCheckerQueueUriShouldNotDefault() {
        assertNull(configurationService.getExperianPhoneCheckerQueueUri());
    }

    @Test
    void getFrontendBaseUrlShouldDefault() {
        assertEquals("", configurationService.getFrontendBaseUrl());
    }

    @Test
    void getOrchestrationToAuthenticationSigningPublicKeysShouldReturnSingleValue() {
        var expectedKey = "expectedKey";
        when(systemService.getenv("ORCH_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY")).thenReturn(expectedKey);
        when(systemService.getOrDefault("ORCH_STUB_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY", ""))
                .thenReturn("");

        ConfigurationService configurationServiceWithMockedSystemService =
                new ConfigurationService();
        configurationServiceWithMockedSystemService.setSystemService(systemService);

        assertEquals(
                Collections.singletonList(expectedKey),
                configurationServiceWithMockedSystemService
                        .getOrchestrationToAuthenticationSigningPublicKeys());
    }

    @Test
    void getOrchestrationToAuthenticationSigningPublicKeysShouldReturnTwoValues() {
        var expectedKey = "expectedKey";
        when(systemService.getenv("ORCH_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY")).thenReturn(expectedKey);
        var secondExpectedKey = "expectedKey2";
        when(systemService.getOrDefault("ORCH_STUB_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY", ""))
                .thenReturn(secondExpectedKey);

        ConfigurationService configurationServiceWithMockedSystemService =
                new ConfigurationService();
        configurationServiceWithMockedSystemService.setSystemService(systemService);

        assertEquals(
                List.of(secondExpectedKey, expectedKey),
                configurationServiceWithMockedSystemService
                        .getOrchestrationToAuthenticationSigningPublicKeys());
    }

    @Test
    void getOrchestrationClientIdShouldDefault() {
        assertEquals("UNKNOWN", configurationService.getOrchestrationClientId());
    }

    @Test
    void getGovUKAccountsURLShouldDefault() {
        assertEquals(URI.create(""), configurationService.getGovUKAccountsURL());
    }

    @Test
    void getHeadersCaseInsensitiveAlwaysFalse() {
        assertFalse(configurationService.getHeadersCaseInsensitive());
    }

    @Test
    void isIdentityEnabledShouldDefault() {
        assertFalse(configurationService.isIdentityEnabled());
    }

    @Test
    void getIDTokenExpiryShouldDefault() {
        assertEquals(120, configurationService.getIDTokenExpiry());
    }

    @Test
    void getNotifyApiUrlShouldDefault() {
        assertFalse(configurationService.getNotifyApiUrl().isPresent());
    }

    @Test
    void getInternalSectorUriShouldNotDefault() {
        assertNull(configurationService.getInternalSectorUri());
    }

    @Test
    void getNotifyApiKeyShouldNotDefault() {
        assertNull(configurationService.getNotifyApiKey());
    }

    @Test
    void shoulCacheTheNotifyBearerTokenAfterTheFirstCall() {
        var mock = mock(SsmClient.class);
        ConfigurationService configurationServiceMockedSsmClient = new ConfigurationService(mock);

        String ssmParamName = "test-notify-callback-bearer-token";
        String ssmParamValue = "bearer-token";

        var request = parameterRequest(ssmParamName);
        var response = parameterResponse(ssmParamName, ssmParamValue);

        when(mock.getParameter(parameterRequest(ssmParamName))).thenReturn(response);

        assertEquals(
                configurationServiceMockedSsmClient.getNotifyCallbackBearerToken(), ssmParamValue);
        assertEquals(
                configurationServiceMockedSsmClient.getNotifyCallbackBearerToken(), ssmParamValue);
        verify(mock, times(1)).getParameter(request);
    }

    @Test
    void getNotifyTestDestinationsShouldDefault() {
        assertEquals(new ArrayList<>(), configurationService.getNotifyTestDestinations());
    }

    @Test
    void shouldGetNotificationTypeFromTemplateId() {
        when(systemService.getenv("VERIFY_EMAIL_TEMPLATE_ID")).thenReturn("1234-abcd");
        when(systemService.getenv("EMAIL_UPDATED_TEMPLATE_ID")).thenReturn("1234-efgh,4567-ijkl");
        when(systemService.getenv("TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID"))
                .thenReturn("1234-bulk");
        when(systemService.getenv("REPORT_SUSPICIOUS_ACTIVITY_EMAIL_TEMPLATE_ID"))
                .thenReturn("report-template-id");

        ConfigurationService configurationServiceWithSystemService = new ConfigurationService();
        configurationServiceWithSystemService.setSystemService(systemService);

        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.VERIFY_EMAIL),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "1234-abcd"));
        assertEquals(
                Optional.empty(),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "1234-wxyz"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.EMAIL_UPDATED),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "4567-ijkl"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.EMAIL_UPDATED),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "1234-efgh"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "1234-bulk"));
        assertEquals(
                Optional.of(DeliveryReceiptsNotificationType.REPORT_SUSPICIOUS_ACTIVITY),
                configurationServiceWithSystemService.getNotificationTypeFromTemplateId(
                        "report-template-id"));
    }

    @Test
    void getOidcApiBaseURLShouldNotDefault() {
        assertTrue(configurationService.getOidcApiBaseURL().isEmpty());
    }

    @Test
    void getReducedLockoutDurationShouldDefault() {
        assertEquals(900, configurationService.getReducedLockoutDuration());
    }

    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        assertEquals(3600, configurationService.getSessionCookieMaxAge());
    }

    @Test
    void getSessionExpiryShouldDefault() {
        assertEquals(3600, configurationService.getSessionExpiry());
    }

    @Test
    void getSmoketestBucketNameShouldNotDefault() {
        assertNull(configurationService.getSmoketestBucketName());
    }

    @Test
    void getSqsEndpointUriShouldNotDefault() {
        assertTrue(configurationService.getSqsEndpointUri().isEmpty());
    }

    @Test
    void getTermsAndConditionsVersionShouldNotDefault() {
        assertNull(configurationService.getTermsAndConditionsVersion());
    }

    @Test
    void getTestClientVerifyEmailOTPShouldNotDefault() {
        assertTrue(configurationService.getTestClientVerifyEmailOTP().isEmpty());
    }

    @Test
    void getTestClientVerifyPhoneNumberOTPShouldNotDefault() {
        assertTrue(configurationService.getTestClientVerifyPhoneNumberOTP().isEmpty());
    }

    @Test
    void isTestClientsEnabledShouldDefault() {
        assertFalse(configurationService.isTestClientsEnabled());
    }

    @Test
    void isPhoneCheckerWithReplyEnabledShouldDefault() {
        assertFalse(configurationService.isPhoneCheckerWithReplyEnabled());
    }

    @Test
    void getSyntheticsUsersShouldDefault() {
        assertEquals("", configurationService.getSyntheticsUsers());
    }

    @Test
    void getTokenSigningKeyAliasShouldNotDefault() {
        assertNull(configurationService.getTokenSigningKeyAlias());
    }

    @Test
    void getTokenSigningKeyRsaAliasShouldNotDefault() {
        assertNull(configurationService.getTokenSigningKeyRsaAlias());
    }

    @Test
    void isRsaSigningAvailableShouldNotDefault() {
        assertFalse(configurationService.isRsaSigningAvailable());
    }

    @Test
    void getNotifyTemplateIdShouldNotDefault() {
        assertNull(configurationService.getNotifyTemplateId("not_there"));
    }

    @Test
    void getTicfCriServiceURIShouldNotDefault() {
        assertNull(configurationService.getTicfCriServiceURI());
    }

    @Test
    void abortOnAccountInterventionsErrorResponseShouldDefault() {
        assertFalse(configurationService.abortOnAccountInterventionsErrorResponse());
    }

    @Test
    void accountInterventionsServiceActionEnabledShouldDefault() {
        assertFalse(configurationService.accountInterventionsServiceActionEnabled());
    }

    @Test
    void isAccountInterventionServiceCallEnabledShouldDefault() {
        assertFalse(configurationService.isAccountInterventionServiceCallEnabled());
    }

    @Test
    void getAccountInterventionServiceCallTimeoutShouldDefault() {
        assertEquals(3000, configurationService.getAccountInterventionServiceCallTimeout());
    }

    @Test
    void getTicfCriServiceCallTimeoutShouldDefault() {
        assertEquals(2000, configurationService.getTicfCriServiceCallTimeout());
    }

    @Test
    void getAccountInterventionsErrorMetricNameShouldDefault() {
        assertEquals("", configurationService.getAccountInterventionsErrorMetricName());
    }

    @Test
    void getIPVAudienceShouldDefault() {
        assertEquals("", configurationService.getIPVAudience());
    }

    @Test
    void getMfaResetStorageTokenSigningKeyAliasShouldNotDefault() {
        assertNull(configurationService.getMfaResetStorageTokenSigningKeyAlias());
    }

    @Test
    void getMfaResetJarSigningKeyAliasShouldNotDefault() {
        assertNull(configurationService.getMfaResetJarSigningKeyAlias());
    }

    @Test
    void getMfaResetJarDeprecatedSigningKeyAliasShouldNotDefault() {
        assertNull(configurationService.getMfaResetJarDeprecatedSigningKeyAlias());
    }

    @Test
    void getMfaResetJarSigningKeyIdShouldNotDefault() {
        assertNull(configurationService.getMfaResetJarSigningKeyId());
    }

    @Test
    void getCredentialStoreURIShouldDefault() {
        assertEquals(
                URI.create("https://credential-store.account.gov.uk"),
                configurationService.getCredentialStoreURI());
    }

    @Test
    void getLegacyAccountDeletionTopicArnShouldNotDefault() {
        assertNull(configurationService.getLegacyAccountDeletionTopicArn());
    }

    @Test
    void getStorageTokenClaimNameShouldDefault() {
        assertEquals(
                "https://vocab.account.gov.uk/v1/storageAccessToken",
                configurationService.getStorageTokenClaimName());
    }

    @Test
    void getAuthIssuerClaimShouldNotDefault() {
        assertEquals("", configurationService.getAuthIssuerClaim());
    }

    @Test
    void getMfaResetCallbackURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getMfaResetCallbackURI());
    }

    @Test
    void getIPVAuthorisationURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getIPVAuthorisationURI());
    }

    @Test
    void getIPVBackendURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getIPVBackendURI());
    }

    @Test
    void getIPVAuthorisationCallbackURIShouldDefault() {
        assertEquals(URI.create(""), configurationService.getIPVAuthorisationCallbackURI());
    }

    @Test
    void getIPVAuthorisationClientIdShouldDefault() {
        assertEquals("", configurationService.getIPVAuthorisationClientId());
    }

    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }

    @Test
    void getAccountCreationLockoutCountTTLShouldEqualDefaultWhenEnvVarUnset() {
        assertEquals(3600, configurationService.getAccountCreationLockoutCountTTL());
    }

    @Test
    void supportAccountCreationTTLShouldEqualDefaultWhenEnvVarUnset() {
        assertFalse(configurationService.supportAccountCreationTTL());
    }

    @Test
    void supportReauthSignoutEnabledShouldEqualDefaultWhenEnvVarUnset() {
        assertFalse(configurationService.supportReauthSignoutEnabled());
    }

    @Test
    void isAuthenticationAttemptsServiceEnabledShouldEqualDefaultWhenEnvVarUnset() {
        assertFalse(configurationService.isAuthenticationAttemptsServiceEnabled());
    }

    @Test
    void getAccountManagementNotifyDestinations() {
        assertNull(configurationService.getAccountManagementNotifyBucketDestination());
    }

    @Test
    void isAccountInterventionServiceCallInAuthenticateEnabledShouldDefaultFalse() {
        assertFalse(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled());
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
        assertEquals(
                result, configurationService.commaSeparatedListContains(searchTerm, searchString));
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
