package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.Audience;
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
import uk.gov.di.orchestration.shared.configuration.AuditPublisherConfiguration;
import uk.gov.di.orchestration.shared.configuration.BaseLambdaConfiguration;
import uk.gov.di.orchestration.shared.exceptions.SSMParameterNotFoundException;

import java.net.URI;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;

public class ConfigurationService implements BaseLambdaConfiguration, AuditPublisherConfiguration {

    private static final Logger LOG = LogManager.getLogger(ConfigurationService.class);
    private static ConfigurationService configurationService;

    public static ConfigurationService getInstance() {
        if (configurationService == null) {
            configurationService = new ConfigurationService();
        }
        return configurationService;
    }

    private SsmClient ssmClient;
    private Map<String, String> ssmRedisParameters;

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

    public boolean isAccountInterventionServiceActionEnabled() {
        return isAccountInterventionServiceCallEnabled()
                && System.getenv()
                        .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED", "false")
                        .equals("true");
    }

    public boolean isAccountInterventionServiceCallEnabled() {
        return System.getenv()
                .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED", "false")
                .equals("true");
    }

    public boolean abortOnAccountInterventionsErrorResponse() {
        return System.getenv()
                .getOrDefault("ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR", "false")
                .equals("true");
    }

    public URI getAccountInterventionServiceURI() {
        return URI.create(System.getenv().getOrDefault("ACCOUNT_INTERVENTION_SERVICE_URI", ""));
    }

    public long getAccountInterventionServiceCallTimeout() {
        return Long.parseLong(
                System.getenv().getOrDefault("ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT", "3000"));
    }

    public String getAccountInterventionsErrorMetricName() {
        return System.getenv().getOrDefault("ACCOUNT_INTERVENTIONS_ERROR_METRIC_NAME", "");
    }

    public URI getAccountStatusBlockedURI() {
        return URI.create(
                System.getenv()
                        .getOrDefault(
                                "ACCOUNT_STATUS_BLOCKED_URI",
                                getFrontendBaseUrl() + "unavailable-permanent"));
    }

    public URI getAccountStatusSuspendedURI() {
        return URI.create(
                System.getenv()
                        .getOrDefault(
                                "ACCOUNT_STATUS_SUSPENDED_URI",
                                getFrontendBaseUrl() + "unavailable-temporary"));
    }

    public long getAuthCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("AUTH_CODE_EXPIRY", "300"));
    }

    public List<String> getBulkUserEmailIncludedTermsAndConditions() {
        String configurationValue =
                systemService.getOrDefault("BULK_USER_EMAIL_INCLUDED_TERMS_AND_CONDITIONS", "");
        if (configurationValue == null || configurationValue.isEmpty()) {
            return List.of();
        } else {
            return Arrays.stream(configurationValue.split(",")).toList();
        }
    }

    public Clock getClock() {
        return Clock.systemDefaultZone();
    }

    public URI getAuthenticationAuthCallbackURI() {
        return URI.create(
                System.getenv().getOrDefault("AUTHENTICATION_AUTHORIZATION_CALLBACK_URI", ""));
    }

    public URI getAuthenticationBackendURI() {
        return URI.create(System.getenv().getOrDefault("AUTHENTICATION_BACKEND_URI", ""));
    }

    public URI getCredentialStoreURI() {
        return URI.create(
                System.getenv()
                        .getOrDefault(
                                "CREDENTIAL_STORE_URI", "https://credential-store.account.gov.uk"));
    }

    public boolean isCustomDocAppClaimEnabled() {
        return System.getenv().getOrDefault("CUSTOM_DOC_APP_CLAIM_ENABLED", "false").equals("true");
    }

    public URI getDefaultLogoutURI() {
        return URI.create(System.getenv("DEFAULT_LOGOUT_URI"));
    }

    public URI getDocAppAuthorisationURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_AUTHORISATION_URI", ""));
    }

    public URI getDocAppBackendURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_BACKEND_URI", ""));
    }

    public URI getDocAppAuthorisationCallbackURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_AUTHORISATION_CALLBACK_URI", ""));
    }

    public String getDocAppAuthorisationClientId() {
        return System.getenv().getOrDefault("DOC_APP_AUTHORISATION_CLIENT_ID", "");
    }

    public String getDocAppEncryptionKeyID() {
        return System.getenv().getOrDefault("DOC_APP_ENCRYPTION_KEY_ID", "");
    }

    public URI getDocAppJwksUri() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_JWKS_URL", ""));
    }

    public String getDocAppTokenSigningKeyAlias() {
        return System.getenv("DOC_APP_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getDocAppCriV2DataEndpoint() {
        return System.getenv("DOC_APP_CRI_DATA_V2_ENDPOINT");
    }

    public boolean isDocAppNewAudClaimEnabled() {
        return System.getenv()
                .getOrDefault("DOC_APP_NEW_AUD_CLAIM_ENABLED", "false")
                .equals("true");
    }

    public Audience getDocAppAudClaim() {
        return new Audience(System.getenv("DOC_APP_AUD"));
    }

    public URI getDocAppDomain() {
        return URI.create(System.getenv("DOC_APP_DOMAIN"));
    }

    public String getDomainName() {
        return System.getenv("DOMAIN_NAME");
    }

    public Optional<String> getDynamoArnPrefix() {
        return Optional.ofNullable(System.getenv("DYNAMO_ARN_PREFIX"));
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }

    public String getSpotQueueUri() {
        return System.getenv("SPOT_QUEUE_URL");
    }

    public String getFrontendBaseUrl() {
        return System.getenv().getOrDefault("FRONTEND_BASE_URL", "");
    }

    public String getOrchestrationToAuthenticationTokenSigningKeyAlias() {
        return System.getenv("ORCH_TO_AUTH_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getOrchestrationToAuthenticationEncryptionPublicKey() {
        var paramName = format("{0}-auth-public-encryption-key", getEnvironment());
        try {
            var request =
                    GetParameterRequest.builder().withDecryption(true).name(paramName).build();
            return getSsmClient().getParameter(request).parameter().value();
        } catch (ParameterNotFoundException e) {
            String message = String.format("No parameter exists with name: %s", paramName);
            LOG.error(message);
            throw new SSMParameterNotFoundException(message, e);
        }
    }

    public String getOrchestrationRedirectUri() {
        return System.getenv().getOrDefault("ORCH_REDIRECT_URI", "orchestration-redirect");
    }

    public String getOrchestrationClientId() {
        return System.getenv().getOrDefault("ORCH_CLIENT_ID", "UNKNOWN");
    }

    public boolean getHeadersCaseInsensitive() {
        return false;
    }

    public boolean isIdentityEnabled() {
        return System.getenv().getOrDefault("IDENTITY_ENABLED", "false").equals("true");
    }

    public boolean isIPVNoSessionResponseEnabled() {
        return System.getenv()
                .getOrDefault("IPV_NO_SESSION_RESPONSE_ENABLED", "false")
                .equals("true");
    }

    public long getIDTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ID_TOKEN_EXPIRY", "120"));
    }

    public URI getIPVAuthorisationURI() {
        return URI.create(System.getenv().getOrDefault("IPV_AUTHORISATION_URI", ""));
    }

    public URI getIPVBackendURI() {
        return URI.create(System.getenv().getOrDefault("IPV_BACKEND_URI", ""));
    }

    public String getIPVAudience() {
        return System.getenv().getOrDefault("IPV_AUDIENCE", "");
    }

    public URI getIPVAuthorisationCallbackURI() {
        return URI.create(System.getenv().getOrDefault("IPV_AUTHORISATION_CALLBACK_URI", ""));
    }

    public String getIPVAuthorisationClientId() {
        return System.getenv().getOrDefault("IPV_AUTHORISATION_CLIENT_ID", "");
    }

    public String getIPVTokenSigningKeyAlias() {
        return System.getenv("IPV_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getIPVAuthEncryptionPublicKey() {
        var paramName = format("{0}-ipv-public-encryption-key", getEnvironment());
        try {
            var request =
                    GetParameterRequest.builder().withDecryption(true).name(paramName).build();
            return getSsmClient().getParameter(request).parameter().value();
        } catch (ParameterNotFoundException e) {
            LOG.error("No parameter exists with name: {}", paramName);
            throw new RuntimeException(e);
        }
    }

    public String getInternalSectorUri() {
        return System.getenv("INTERNAl_SECTOR_URI");
    }

    public URI getLoginURI() {
        return URI.create(System.getenv("LOGIN_URI"));
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

    public Optional<String> getOidcApiBaseURL() {
        return Optional.ofNullable(System.getenv("OIDC_API_BASE_URL"));
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

    public int getPersistentCookieMaxAge() {
        return Integer.parseInt(
                System.getenv().getOrDefault("PERSISTENT_COOKIE_MAX_AGE", "34190000"));
    }

    public int getLanguageCookieMaxAge() {
        return Integer.parseInt(
                System.getenv().getOrDefault("LANGUAGE_COOKIE_MAX_AGE", "31536000"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "3600"));
    }

    public String getStorageTokenClaimName() {
        return System.getenv()
                .getOrDefault(
                        "STORAGE_TOKEN_CLAIM_NAME",
                        "https://vocab.account.gov.uk/v1/storageAccessToken");
    }

    public boolean sendStorageTokenToIpvEnabled() {
        return System.getenv()
                .getOrDefault("SEND_STORAGE_TOKEN_TO_IPV_ENABLED", "false")
                .equals("true");
    }

    public Optional<String> getSqsEndpointUri() {
        return Optional.ofNullable(System.getenv("SQS_ENDPOINT"));
    }

    public boolean isTestClientsEnabled() {
        return System.getenv().getOrDefault("TEST_CLIENTS_ENABLED", "false").equals("true");
    }

    public String getExternalTokenSigningKeyAlias() {
        return System.getenv("EXTERNAL_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getExternalTokenSigningKeyRsaAlias() {
        return System.getenv("EXTERNAL_TOKEN_SIGNING_KEY_RSA_ALIAS");
    }

    public boolean isRsaSigningAvailable() {
        return List.of("build", "staging", "integration", "production").contains(getEnvironment());
    }

    public String getStorageTokenSigningKeyAlias() {
        return System.getenv("STORAGE_TOKEN_SIGNING_KEY_ALIAS");
    }

    public Optional<String> getIPVCapacity() {
        try {
            var request =
                    GetParameterRequest.builder()
                            .withDecryption(true)
                            .name(format("{0}-ipv-capacity", getEnvironment()))
                            .build();
            return Optional.of(getSsmClient().getParameter(request).parameter().value());
        } catch (ParameterNotFoundException e) {
            return Optional.empty();
        }
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

    public String getBackChannelLogoutQueueUri() {
        return System.getenv("BACK_CHANNEL_LOGOUT_QUEUE_URI");
    }

    public String getNotifyTemplateId(String templateName) {
        return System.getenv(templateName);
    }

    public boolean isTxmaAuditEncodedEnabled() {
        return System.getenv().getOrDefault("TXMA_AUDIT_ENCODED_ENABLED", "false").equals("true");
    }
}
