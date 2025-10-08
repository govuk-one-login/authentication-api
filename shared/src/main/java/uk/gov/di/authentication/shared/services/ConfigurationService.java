package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParametersRequest;
import software.amazon.awssdk.services.ssm.model.Parameter;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import uk.gov.di.authentication.shared.configuration.AuditPublisherConfiguration;
import uk.gov.di.authentication.shared.configuration.BaseLambdaConfiguration;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;
import uk.gov.di.authentication.shared.exceptions.MissingEnvVariableException;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static java.util.Objects.isNull;
import static uk.gov.di.authentication.entity.Environment.INTEGRATION;
import static uk.gov.di.authentication.entity.Environment.PRODUCTION;

public class ConfigurationService implements BaseLambdaConfiguration, AuditPublisherConfiguration {

    private static final Logger LOG = LogManager.getLogger(ConfigurationService.class);
    public static final String FEATURE_SWITCH_OFF = "false";
    public static final String FEATURE_SWITCH_ON = "true";
    private static ConfigurationService configurationService;

    public static ConfigurationService getInstance() {
        if (configurationService == null) {
            configurationService = new ConfigurationService();
        }
        return configurationService;
    }

    private SsmClient ssmClient;
    private Map<String, String> ssmRedisParameters;
    private Optional<String> passwordPepper;

    private String notifyCallbackBearerToken;
    protected SystemService systemService;

    public ConfigurationService() {}

    protected ConfigurationService(SsmClient ssmClient) {
        this.ssmClient = ssmClient;
    }

    public void setSystemService(SystemService systemService) {
        this.systemService = systemService;
    }

    // Please keep the method names in alphabetical order so we can find stuff more easily.
    public long getAccessTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ACCESS_TOKEN_EXPIRY", "180"));
    }

    public String getAccountManagementURI() {
        return System.getenv("ACCOUNT_MANAGEMENT_URI");
    }

    public long getAuthCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("AUTH_CODE_EXPIRY", "300"));
    }

    public long getIncorrectPasswordLockoutCountTTL() {
        return Long.parseLong(
                System.getenv().getOrDefault("INCORRECT_PASSWORD_LOCKOUT_COUNT_TTL", "900"));
    }

    public long getLockoutCountTTL() {
        return Long.parseLong(System.getenv().getOrDefault("LOCKOUT_COUNT_TTL", "900"));
    }

    public long getAccountCreationLockoutCountTTL() {
        return Long.parseLong(
                System.getenv().getOrDefault("ACCOUNT_CREATION_LOCKOUT_COUNT_TTL", "3600"));
    }

    public long getReauthEnterEmailCountTTL() {
        return Long.parseLong(System.getenv().getOrDefault("REAUTH_ENTER_EMAIL_COUNT_TTL", "3600"));
    }

    public long getReauthEnterPasswordCountTTL() {
        return Long.parseLong(
                System.getenv().getOrDefault("REAUTH_ENTER_PASSWORD_COUNT_TTL", "3600"));
    }

    public long getReauthEnterAuthAppCodeCountTTL() {
        return Long.parseLong(
                System.getenv().getOrDefault("REAUTH_ENTER_AUTH_APP_CODE_COUNT_TTL", "3600"));
    }

    public long getReauthEnterSMSCodeCountTTL() {
        return Long.parseLong(
                System.getenv().getOrDefault("REAUTH_ENTER_SMS_CODE_COUNT_TTL", "3600"));
    }

    public boolean supportAccountCreationTTL() {
        return System.getenv()
                .getOrDefault("SUPPORT_ACCOUNT_CREATION_COUNT_TTL", String.valueOf(false))
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean supportReauthSignoutEnabled() {
        return System.getenv()
                .getOrDefault("SUPPORT_REAUTH_SIGNOUT_ENABLED", String.valueOf(false))
                .equals("true");
    }

    public boolean isAuthenticationAttemptsServiceEnabled() {
        return System.getenv()
                .getOrDefault("AUTHENTICATION_ATTEMPTS_SERVICE_ENABLED", String.valueOf(false))
                .equals("true");
    }

    public long getLockoutDuration() {
        return Long.parseLong(System.getenv().getOrDefault("LOCKOUT_DURATION", "900"));
    }

    public long getReducedLockoutDuration() {
        return Long.parseLong(System.getenv().getOrDefault("REDUCED_LOCKOUT_DURATION", "900"));
    }

    public int getBulkUserEmailBatchQueryLimit() {
        return Integer.parseInt(
                System.getenv().getOrDefault("BULK_USER_EMAIL_BATCH_QUERY_LIMIT", "25"));
    }

    public int getBulkUserEmailMaxBatchCount() {
        return Integer.parseInt(
                System.getenv().getOrDefault("BULK_USER_EMAIL_MAX_BATCH_COUNT", "20"));
    }

    public long getBulkUserEmailMaxAudienceLoadUserCount() {
        return Long.parseLong(
                System.getenv().getOrDefault("BULK_USER_EMAIL_MAX_AUDIENCE_LOAD_USER_COUNT", "0"));
    }

    public long getBulkUserEmailAudienceLoadUserBatchSize() {
        return Long.parseLong(
                System.getenv()
                        .getOrDefault("BULK_USER_EMAIL_MAX_AUDIENCE_LOAD_USER_BATCH_SIZE", "0"));
    }

    public long getBulkUserEmailBatchPauseDuration() {
        return Long.parseLong(
                System.getenv().getOrDefault("BULK_USER_EMAIL_BATCH_PAUSE_DURATION", "0"));
    }

    public List<String> getBulkUserEmailIncludedTermsAndConditions() {
        String configurationValue =
                systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", "");
        if (configurationValue == null || configurationValue.isEmpty()) {
            return List.of();
        } else {
            return Arrays.stream(configurationValue.split(",")).collect(Collectors.toList());
        }
    }

    public String getBulkEmailUserSendMode() {
        return systemService.getOrDefault("BULK_USER_EMAIL_SEND_MODE", "PENDING");
    }

    public boolean isBulkUserEmailEnabled() {
        return System.getenv().getOrDefault("BULK_USER_EMAIL_ENABLED", "0").equals("1");
    }

    public long getDefaultOtpCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("DEFAULT_OTP_CODE_EXPIRY", "900"));
    }

    public Clock getClock() {
        return Clock.systemDefaultZone();
    }

    public long getEmailAccountCreationOtpCodeExpiry() {
        return Long.parseLong(
                System.getenv().getOrDefault("EMAIL_OTP_ACCOUNT_CREATION_CODE_EXPIRY", "3600"));
    }

    public int getCodeMaxRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_MAX_RETRIES", "6"));
    }

    public int getIncreasedCodeMaxRetries() {
        return Integer.parseInt(
                System.getenv().getOrDefault("CODE_MAX_RETRIES_INCREASED", "999999"));
    }

    public int getAuthAppCodeWindowLength() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_AUTH_APP_WINDOW_LENGTH", "30"));
    }

    public int getAuthAppCodeAllowedWindows() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_AUTH_APP_ALLOWED_WINDOWS", "9"));
    }

    public boolean isBulkUserEmailEmailSendingEnabled() {
        return System.getenv()
                .getOrDefault("BULK_USER_EMAIL_EMAIL_SENDING_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public String getBulkEmailLoaderLambdaName() {
        return System.getenv().getOrDefault("BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME", "");
    }

    public String getTicfCRILambdaIdentifier() {
        return System.getenv().getOrDefault("TICF_CRI_LAMBDA_IDENTIFIER", "");
    }

    public boolean isInvokeTicfCRILambdaEnabled() {
        return System.getenv()
                .getOrDefault("INVOKE_TICF_CRI_LAMBDA", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public URI getAuthenticationAuthCallbackURI() {
        return URI.create(
                System.getenv().getOrDefault("AUTHENTICATION_AUTHORIZATION_CALLBACK_URI", ""));
    }

    public URI getAuthenticationBackendURI() {
        return URI.create(System.getenv().getOrDefault("AUTHENTICATION_BACKEND_URI", ""));
    }

    public URI getOrchestrationBackendURI() {
        return URI.create(System.getenv().getOrDefault("ORCHESTRATION_BACKEND_URI", ""));
    }

    public String getContactUsLinkRoute() {
        return System.getenv().getOrDefault("CONTACT_US_LINK_ROUTE", "");
    }

    public int getMaxPasswordRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("PASSWORD_MAX_RETRIES", "6"));
    }

    public int getMaxEmailReAuthRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("EMAIL_MAX_RE_AUTH_RETRIES", "6"));
    }

    public boolean isCustomDocAppClaimEnabled() {
        return System.getenv()
                .getOrDefault("CUSTOM_DOC_APP_CLAIM_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public URI getDocAppAuthorisationURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_AUTHORISATION_URI", ""));
    }

    public URI getDocAppAuthorisationCallbackURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_AUTHORISATION_CALLBACK_URI", ""));
    }

    public String getDocAppAuthorisationClientId() {
        return System.getenv().getOrDefault("DOC_APP_AUTHORISATION_CLIENT_ID", "");
    }

    public URI getDocAppJwksUri() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_JWKS_URL", ""));
    }

    public String getDocAppTokenSigningKeyAlias() {
        return System.getenv("DOC_APP_TOKEN_SIGNING_KEY_ALIAS");
    }

    public URI getDocAppDomain() {
        return URI.create(System.getenv("DOC_APP_DOMAIN"));
    }

    public Optional<String> getDynamoArnPrefix() {
        return Optional.ofNullable(System.getenv("DYNAMO_ARN_PREFIX"));
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }

    public String getEmailQueueUri() {
        return System.getenv("EMAIL_QUEUE_URL");
    }

    public String getPendingEmailCheckQueueUri() {
        return System.getenv("PENDING_EMAIL_CHECK_QUEUE_URL");
    }

    public String getExperianPhoneCheckerQueueUri() {
        return System.getenv("EXPERIAN_PHONE_CHECKER_QUEUE_URL");
    }

    public String getFrontendBaseUrl() {
        return System.getenv().getOrDefault("FRONTEND_BASE_URL", "");
    }

    public List<String> getOrchestrationToAuthenticationSigningPublicKeys() {
        var orchKey = getOrchestrationToAuthenticationSigningPublicKey();
        var orchStubKey = getOrchestrationStubToAuthenticationSigningPublicKey();
        return orchStubKey
                .map(stubKey -> List.of(stubKey, orchKey))
                .orElseGet(() -> List.of(orchKey));
    }

    private String getOrchestrationToAuthenticationSigningPublicKey() {
        return systemService.getenv("ORCH_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY");
    }

    private Optional<String> getOrchestrationStubToAuthenticationSigningPublicKey() {
        var orchStubKey =
                systemService.getOrDefault("ORCH_STUB_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY", "");
        if (orchStubKey.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(orchStubKey);
    }

    public String getOrchestrationClientId() {
        return System.getenv().getOrDefault("ORCH_CLIENT_ID", "UNKNOWN");
    }

    public URI getGovUKAccountsURL() {
        return URI.create(System.getenv().getOrDefault("GOV_UK_ACCOUNTS_URL", ""));
    }

    public boolean getHeadersCaseInsensitive() {
        return false;
    }

    public boolean isIdentityEnabled() {
        return System.getenv()
                .getOrDefault("IDENTITY_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public long getIDTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ID_TOKEN_EXPIRY", "120"));
    }

    public Optional<String> getNotifyApiUrl() {
        return Optional.ofNullable(System.getenv("NOTIFY_URL"));
    }

    public String getInternalSectorUri() {
        return System.getenv("INTERNAl_SECTOR_URI");
    }

    public String getNotifyApiKey() {
        return System.getenv("NOTIFY_API_KEY");
    }

    public String getNotifyCallbackBearerToken() {
        if (notifyCallbackBearerToken == null) {

            var request =
                    GetParameterRequest.builder()
                            .withDecryption(true)
                            .name(format("{0}-notify-callback-bearer-token", getEnvironment()))
                            .build();

            notifyCallbackBearerToken = getSsmClient().getParameter(request).parameter().value();
        }

        return notifyCallbackBearerToken;
    }

    public List<String> getNotifyTestDestinations() {
        var destinations = System.getenv("NOTIFY_TEST_DESTINATIONS");
        return isNull(destinations) || destinations.isBlank()
                ? List.of()
                : Arrays.stream(destinations.split(",")).collect(Collectors.toList());
    }

    public Optional<DeliveryReceiptsNotificationType> getNotificationTypeFromTemplateId(
            String templateId) {
        for (DeliveryReceiptsNotificationType type : DeliveryReceiptsNotificationType.values()) {
            if (commaSeparatedListContains(
                    templateId, systemService.getenv(type.getTemplateName()))) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    boolean commaSeparatedListContains(String searchTerm, String stringToSearch) {
        return (searchTerm != null
                && !searchTerm.isBlank()
                && stringToSearch != null
                && !stringToSearch.isBlank()
                && Arrays.stream(stringToSearch.split(",")).anyMatch(id -> id.equals(searchTerm)));
    }

    public Optional<String> getOidcApiBaseURL() {
        return Optional.ofNullable(System.getenv("OIDC_API_BASE_URL"));
    }

    public Optional<String> getPasswordPepper() {
        if (passwordPepper == null) {
            try {
                var request =
                        GetParameterRequest.builder()
                                .withDecryption(true)
                                .name(format("{0}-password-pepper", getEnvironment()))
                                .build();
                passwordPepper =
                        Optional.of(getSsmClient().getParameter(request).parameter().value());
            } catch (ParameterNotFoundException e) {
                passwordPepper = Optional.empty();
            }
        }
        return passwordPepper;
    }

    public String getRedisHost() {
        return getSsmRedisParameters()
                .get(format("{0}-{1}-redis-master-host", getEnvironment(), getRedisKey()));
    }

    public Optional<String> getRedisPassword() {
        return Optional.ofNullable(
                getSsmRedisParameters()
                        .get(format("{0}-{1}-redis-password", getEnvironment(), getRedisKey())));
    }

    public int getRedisPort() {
        return Integer.parseInt(
                getSsmRedisParameters()
                        .get(format("{0}-{1}-redis-port", getEnvironment(), getRedisKey())));
    }

    public boolean getUseRedisTLS() {
        return Boolean.parseBoolean(
                getSsmRedisParameters()
                        .get(format("{0}-{1}-redis-tls", getEnvironment(), getRedisKey())));
    }

    public String getSessionCookieAttributes() {
        return Optional.ofNullable(System.getenv("SESSION_COOKIE_ATTRIBUTES"))
                .orElse("Secure; HttpOnly;");
    }

    public int getSessionCookieMaxAge() {
        return Integer.parseInt(System.getenv().getOrDefault("SESSION_COOKIE_MAX_AGE", "3600"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "3600"));
    }

    public String getSmoketestBucketName() {
        return System.getenv("SMOKETEST_SMS_BUCKET_NAME");
    }

    public String getAccountManagementNotifyBucketDestination() {
        return System.getenv("ACCOUNT_MANAGEMENT_NOTIFY_ALTERNATIVE_DESTINATION");
    }

    public Optional<String> getSqsEndpointUri() {
        return Optional.ofNullable(System.getenv("SQS_ENDPOINT"));
    }

    public String getSnsEndpointUri() {
        return System.getenv("SNS_ENDPOINT");
    }

    public String getTermsAndConditionsVersion() {
        return System.getenv("TERMS_CONDITIONS_VERSION");
    }

    public Optional<String> getTestClientVerifyEmailOTP() {
        return Optional.ofNullable(System.getenv("TEST_CLIENT_VERIFY_EMAIL_OTP"));
    }

    public Optional<String> getTestClientVerifyPhoneNumberOTP() {
        return Optional.ofNullable(System.getenv("TEST_CLIENT_VERIFY_PHONE_NUMBER_OTP"));
    }

    public boolean isAccountInterventionServiceCallInAuthenticateEnabled() {
        return System.getenv()
                .getOrDefault(
                        "ACCOUNT_INTERVENTION_SERVICE_CALL_IN_AUTHENTICATE_ENABLED",
                        FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean isTestClientsEnabled() {
        return System.getenv()
                .getOrDefault("TEST_CLIENTS_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean isPhoneCheckerWithReplyEnabled() {
        return System.getenv()
                .getOrDefault("PHONE_CHECKER_WITH_RETRY", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public String getSyntheticsUsers() {
        return System.getenv().getOrDefault("SYNTHETICS_USERS", "");
    }

    public String getTokenSigningKeyAlias() {
        return System.getenv("TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getTokenSigningKeyRsaAlias() {
        return System.getenv("TOKEN_SIGNING_KEY_RSA_ALIAS");
    }

    public boolean isRsaSigningAvailable() {
        return List.of("build", "staging", "integration", "production").contains(getEnvironment());
    }

    private Map<String, String> getSsmRedisParameters() {
        if (ssmRedisParameters == null) {
            var getParametersRequest =
                    GetParametersRequest.builder()
                            .names(
                                    format(
                                            "{0}-{1}-redis-master-host",
                                            getEnvironment(), getRedisKey()),
                                    format(
                                            "{0}-{1}-redis-password",
                                            getEnvironment(), getRedisKey()),
                                    format("{0}-{1}-redis-port", getEnvironment(), getRedisKey()),
                                    format("{0}-{1}-redis-tls", getEnvironment(), getRedisKey()))
                            .withDecryption(true)
                            .build();
            var result = getSsmClient().getParameters(getParametersRequest);
            ssmRedisParameters =
                    result.parameters().stream()
                            .collect(Collectors.toMap(Parameter::name, Parameter::value));
        }
        return ssmRedisParameters;
    }

    private SsmClient getSsmClient() {
        if (ssmClient == null) {
            ssmClient =
                    getLocalstackEndpointUri()
                            .map(
                                    l -> {
                                        LOG.info("Localstack endpoint URI is present: " + l);
                                        return SsmClient.builder()
                                                .region(Region.of(getAwsRegion()))
                                                .endpointOverride(URI.create(l))
                                                .credentialsProvider(
                                                        StaticCredentialsProvider.create(
                                                                AwsBasicCredentials.create(
                                                                        "FAKEACCESSKEY",
                                                                        "FAKESECRETKEY")))
                                                .build();
                                    })
                            .orElseGet(
                                    () ->
                                            SsmClient.builder()
                                                    .region(Region.of(getAwsRegion()))
                                                    .build());
        }
        return ssmClient;
    }

    private String getRedisKey() {
        return System.getenv("REDIS_KEY");
    }

    public String getNotifyTemplateId(String templateName) {
        return System.getenv(templateName);
    }

    public URI getAccountInterventionServiceURI() {
        return URI.create(System.getenv("ACCOUNT_INTERVENTION_SERVICE_URI"));
    }

    public String getTicfCriServiceURI() {
        return System.getenv("TICF_CRI_SERVICE_URI");
    }

    public boolean abortOnAccountInterventionsErrorResponse() {
        return System.getenv()
                .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean accountInterventionsServiceActionEnabled() {
        return System.getenv()
                .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean isAccountInterventionServiceCallEnabled() {
        return System.getenv()
                .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public long getAccountInterventionServiceCallTimeout() {
        return Long.parseLong(
                System.getenv().getOrDefault("ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT", "3000"));
    }

    public long getTicfCriServiceCallTimeout() {
        return Long.parseLong(
                System.getenv().getOrDefault("TICF_CRI_SERVICE_CALL_TIMEOUT", "2000"));
    }

    public String getAccountInterventionsErrorMetricName() {
        return System.getenv().getOrDefault("ACCOUNT_INTERVENTIONS_ERROR_METRIC_NAME", "");
    }

    public String getIPVAudience() {
        return System.getenv().getOrDefault("IPV_AUDIENCE", "");
    }

    public String getMfaResetStorageTokenSigningKeyAlias() {
        return System.getenv("MFA_RESET_STORAGE_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getMfaResetJarSigningKeyAlias() {
        return System.getenv("IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS");
    }

    public String getMfaResetJarDeprecatedSigningKeyAlias() {
        return System.getenv("IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS");
    }

    public String getMfaResetJarSigningKeyId() {
        return System.getenv("IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS");
    }

    public URI getCredentialStoreURI() {
        return getURIOrDefault("CREDENTIAL_STORE_URI", "https://credential-store.account.gov.uk");
    }

    public String getLegacyAccountDeletionTopicArn() {
        return System.getenv("LEGACY_ACCOUNT_DELETION_TOPIC_ARN");
    }

    private URI getURIOrDefault(String envVar, String defaultUri) {
        return getOptionalURI(envVar).orElseGet(() -> URI.create(defaultUri));
    }

    private Optional<URI> getOptionalURI(String envVar) {
        return System.getenv().containsKey(envVar)
                ? Optional.of(URI.create(System.getenv(envVar)))
                : Optional.empty();
    }

    public String getStorageTokenClaimName() {
        return System.getenv()
                .getOrDefault(
                        "STORAGE_TOKEN_CLAIM_NAME",
                        "https://vocab.account.gov.uk/v1/storageAccessToken");
    }

    public String getAuthIssuerClaim() {
        return System.getenv().getOrDefault("AUTH_ISSUER_CLAIM", "");
    }

    public String getAuthIssuerClaimForEVCS() {
        return System.getenv().getOrDefault("AUTH_ISSUER_CLAIM_FOR_EVCS", "");
    }

    public String getEVCSAudience() {
        return System.getenv().getOrDefault("EVCS_AUDIENCE", "");
    }

    public URI getMfaResetCallbackURI() {
        return getURIOrDefault("MFA_RESET_CALLBACK_URI", "");
    }

    public String getIPVAuthEncryptionPublicKey() throws MissingEnvVariableException {
        String key = System.getenv("IPV_PUBLIC_ENCRYPTION_KEY");
        if (key == null || key.isEmpty()) {
            throw new MissingEnvVariableException("IPV_PUBLIC_ENCRYPTION_KEY");
        }
        return key;
    }

    public URI getIPVAuthorisationURI() {
        return getURIOrDefault("IPV_AUTHORIZATION_URI", "");
    }

    public URI getIPVBackendURI() {
        return URI.create(System.getenv().getOrDefault("IPV_BACKEND_URI", ""));
    }

    public URI getIPVAuthorisationCallbackURI() {
        return URI.create(System.getenv().getOrDefault("IPV_AUTHORISATION_CALLBACK_URI", ""));
    }

    public String getIPVAuthorisationClientId() {
        return System.getenv().getOrDefault("IPV_AUTHORISATION_CLIENT_ID", "");
    }

    public boolean isMfaMethodManagementApiEnabled() {
        return System.getenv()
                .getOrDefault("MFA_METHOD_MANAGEMENT_API_ENABLED", String.valueOf(false))
                .equals(FEATURE_SWITCH_ON);
    }

    public boolean isUsingStronglyConsistentReads() {
        return System.getenv()
                .getOrDefault("USE_STRONGLY_CONSISTENT_READS", FEATURE_SWITCH_OFF)
                .equals(FEATURE_SWITCH_ON);
    }

    public URL getIpvJwksUrl() throws MalformedURLException {
        try {
            return new URL(System.getenv().getOrDefault("IPV_JWKS_URL", ""));
        } catch (MalformedURLException e) {
            LOG.error("Invalid JWKS URL: {}", e.getMessage());
            throw new MalformedURLException(e.getMessage());
        }
    }

    public boolean isIpvJwksCallEnabled() {
        return System.getenv()
                .getOrDefault("IPV_JWKS_CALL_ENABLED", String.valueOf(false))
                .equals(FEATURE_SWITCH_ON);
    }

    public double getDomesticSmsQuotaThreshold() {
        return Double.parseDouble(
                System.getenv().getOrDefault("DOMESTIC_SMS_QUOTA_THRESHOLD", "20000"));
    }

    public double getInternationalSmsQuotaThreshold() {
        return Double.parseDouble(
                System.getenv().getOrDefault("INTERNATIONAL_SMS_QUOTA_THRESHOLD", "5000"));
    }

    public boolean isBulkAccountDeletionEnabled() {
        return !List.of(INTEGRATION.getValue(), PRODUCTION.getValue()).contains(getEnvironment());
    }
}
