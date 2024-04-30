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
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

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

    private final Map<String, String> env;

    public ConfigurationService() {
        this(System.getenv());
    }

    protected ConfigurationService(Map<String, String> env) {
        this.env = env;
    }

    protected ConfigurationService(SsmClient ssmClient) {
        this();
        this.ssmClient = ssmClient;
    }

    protected ConfigurationService(SystemService systemService) {
        this();
        this.systemService = systemService;
    }

    private boolean getFlagOrFalse(String envVar) {
        return env.containsKey(envVar) && Boolean.parseBoolean(env.get(envVar));
    }

    private URI getURIOrDefault(String envVar, String defaultUri) {
        return getOptionalURI(envVar).orElseGet(() -> URI.create(defaultUri));
    }

    private URI getURIOrEmpty(String envVar) {
        return getURIOrDefault(envVar, "");
    }

    private URI getURIOrThrow(String envVar) {
        return getOptionalURI(envVar).orElseThrow();
    }

    private Optional<URI> getOptionalURI(String envVar) {
        return env.containsKey(envVar)
                ? Optional.of(URI.create(env.get(envVar)))
                : Optional.empty();
    }

    // Please keep the method names in alphabetical order so we can find stuff more easily.
    public long getAccessTokenExpiry() {
        return Long.parseLong(env.getOrDefault("ACCESS_TOKEN_EXPIRY", "180"));
    }

    public boolean isAccountInterventionServiceActionEnabled() {
        return isAccountInterventionServiceCallEnabled()
                && getFlagOrFalse("ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED");
    }

    public boolean isAccountInterventionServiceCallEnabled() {
        return getFlagOrFalse("ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED");
    }

    public boolean abortOnAccountInterventionsErrorResponse() {
        return getFlagOrFalse("ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR");
    }

    public URI getAccountInterventionServiceURI() {
        return getURIOrEmpty("ACCOUNT_INTERVENTION_SERVICE_URI");
    }

    public long getAccountInterventionServiceCallTimeout() {
        return Long.parseLong(
                env.getOrDefault("ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT", "3000"));
    }

    public String getAccountInterventionsErrorMetricName() {
        return env.getOrDefault("ACCOUNT_INTERVENTIONS_ERROR_METRIC_NAME", "");
    }

    public URI getAccountStatusBlockedURI() {
        return getURIOrDefault(
                "ACCOUNT_STATUS_BLOCKED_URI", getFrontendBaseURL() + "unavailable-permanent");
    }

    public URI getAccountStatusSuspendedURI() {
        return getURIOrDefault(
                "ACCOUNT_STATUS_SUSPENDED_URI", getFrontendBaseURL() + "unavailable-temporary");
    }

    public long getAuthCodeExpiry() {
        return Long.parseLong(env.getOrDefault("AUTH_CODE_EXPIRY", "300"));
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
        return getURIOrEmpty("AUTHENTICATION_AUTHORIZATION_CALLBACK_URI");
    }

    public URI getAuthenticationBackendURI() {
        return getURIOrEmpty("AUTHENTICATION_BACKEND_URI");
    }

    public URI getCredentialStoreURI() {
        return getURIOrDefault("CREDENTIAL_STORE_URI", "https://credential-store.account.gov.uk");
    }

    public boolean isCustomDocAppClaimEnabled() {
        return getFlagOrFalse("CUSTOM_DOC_APP_CLAIM_ENABLED");
    }

    public URI getDefaultLogoutURI() {
        return getURIOrThrow("DEFAULT_LOGOUT_URI");
    }

    public URI getDocAppAuthorisationURI() {
        return getURIOrEmpty("DOC_APP_AUTHORISATION_URI");
    }

    public URI getDocAppBackendURI() {
        return getURIOrEmpty("DOC_APP_BACKEND_URI");
    }

    public URI getDocAppAuthorisationCallbackURI() {
        return getURIOrEmpty("DOC_APP_AUTHORISATION_CALLBACK_URI");
    }

    public String getDocAppAuthorisationClientId() {
        return env.getOrDefault("DOC_APP_AUTHORISATION_CLIENT_ID", "");
    }

    public String getDocAppEncryptionKeyID() {
        return env.getOrDefault("DOC_APP_ENCRYPTION_KEY_ID", "");
    }

    public URI getDocAppJwksURI() {
        return getURIOrEmpty("DOC_APP_JWKS_URL");
    }

    public String getDocAppTokenSigningKeyAlias() {
        return env.get("DOC_APP_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getDocAppCriDataEndpoint() {
        return env.get("DOC_APP_CRI_DATA_ENDPOINT");
    }

    public String getDocAppCriV2DataEndpoint() {
        return env.get("DOC_APP_CRI_DATA_V2_ENDPOINT");
    }

    public boolean isDocAppNewAudClaimEnabled() {
        return getFlagOrFalse("DOC_APP_NEW_AUD_CLAIM_ENABLED");
    }

    public Audience getDocAppAudClaim() {
        return new Audience(env.get("DOC_APP_AUD"));
    }

    public URI getDocAppDomain() {
        return getURIOrThrow("DOC_APP_DOMAIN");
    }

    public String getDomainName() {
        return env.get("DOMAIN_NAME");
    }

    public Optional<String> getDynamoArnPrefix() {
        return Optional.ofNullable(env.get("DYNAMO_ARN_PREFIX"));
    }

    public Optional<URI> getDynamoEndpointURI() {
        return getOptionalURI("DYNAMO_ENDPOINT");
    }

    public URI getSpotQueueURI() {
        return getURIOrEmpty("SPOT_QUEUE_URL");
    }

    public URI getFrontendBaseURL() {
        return getURIOrEmpty("FRONTEND_BASE_URL");
    }

    public String getOrchestrationToAuthenticationTokenSigningKeyAlias() {
        return env.get("ORCH_TO_AUTH_TOKEN_SIGNING_KEY_ALIAS");
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

    public URI getOrchestrationRedirectURI() {
        return getURIOrDefault("ORCH_REDIRECT_URI", "orchestration-redirect");
    }

    public String getOrchestrationClientId() {
        return env.getOrDefault("ORCH_CLIENT_ID", "UNKNOWN");
    }

    public boolean getHeadersCaseInsensitive() {
        return false;
    }

    public boolean isIdentityEnabled() {
        return getFlagOrFalse("IDENTITY_ENABLED");
    }

    public boolean isIPVNoSessionResponseEnabled() {
        return getFlagOrFalse("IPV_NO_SESSION_RESPONSE_ENABLED");
    }

    public long getIDTokenExpiry() {
        return Long.parseLong(env.getOrDefault("ID_TOKEN_EXPIRY", "120"));
    }

    public URI getIPVAuthorisationURI() {
        return getURIOrEmpty("IPV_AUTHORISATION_URI");
    }

    public URI getIPVBackendURI() {
        return getURIOrEmpty("IPV_BACKEND_URI");
    }

    public URI getIPVAudience() {
        return getURIOrEmpty("IPV_AUDIENCE");
    }

    public URI getIPVAuthorisationCallbackURI() {
        return getURIOrEmpty("IPV_AUTHORISATION_CALLBACK_URI");
    }

    public String getIPVAuthorisationClientId() {
        return env.getOrDefault("IPV_AUTHORISATION_CLIENT_ID", "");
    }

    public String getIPVTokenSigningKeyAlias() {
        return env.get("IPV_TOKEN_SIGNING_KEY_ALIAS");
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

    public URI getInternalSectorURI() {
        return getURIOrThrow("INTERNAl_SECTOR_URI");
    }

    public URI getLoginURI() {
        return getURIOrThrow("LOGIN_URI");
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

    boolean commaSeparatedListContains(String searchTerm, String stringToSearch) {
        return (searchTerm != null
                && !searchTerm.isBlank()
                && stringToSearch != null
                && !stringToSearch.isBlank()
                && Arrays.stream(stringToSearch.split(",")).anyMatch(id -> id.equals(searchTerm)));
    }

    public Optional<URI> getOidcApiBaseURL() {
        return getOptionalURI("OIDC_API_BASE_URL");
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
        return Optional.ofNullable(env.get("SESSION_COOKIE_ATTRIBUTES"))
                .orElse("Secure; HttpOnly;");
    }

    public int getSessionCookieMaxAge() {
        return Integer.parseInt(env.getOrDefault("SESSION_COOKIE_MAX_AGE", "3600"));
    }

    public int getPersistentCookieMaxAge() {
        return Integer.parseInt(env.getOrDefault("PERSISTENT_COOKIE_MAX_AGE", "34190000"));
    }

    public int getLanguageCookieMaxAge() {
        return Integer.parseInt(env.getOrDefault("LANGUAGE_COOKIE_MAX_AGE", "31536000"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(env.getOrDefault("SESSION_EXPIRY", "3600"));
    }

    public URI getStorageTokenClaimName() {
        return getURIOrDefault(
                "STORAGE_TOKEN_CLAIM_NAME", "https://vocab.account.gov.uk/v1/storageAccessToken");
    }

    public boolean sendStorageTokenToIpvEnabled() {
        return getFlagOrFalse("SEND_STORAGE_TOKEN_TO_IPV_ENABLED");
    }

    public Optional<URI> getSqsEndpointURI() {
        return getOptionalURI("SQS_ENDPOINT");
    }

    public boolean isTestClientsEnabled() {
        return getFlagOrFalse("TEST_CLIENTS_ENABLED");
    }

    public String getExternalTokenSigningKeyAlias() {
        return env.get("EXTERNAL_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getExternalTokenSigningKeyRsaAlias() {
        return env.get("EXTERNAL_TOKEN_SIGNING_KEY_RSA_ALIAS");
    }

    public boolean isRsaSigningAvailable() {
        return List.of("build", "staging", "integration", "production").contains(getEnvironment());
    }

    public String getStorageTokenSigningKeyAlias() {
        return env.get("STORAGE_TOKEN_SIGNING_KEY_ALIAS");
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
        return env.get("REDIS_KEY");
    }

    public URI getBackChannelLogoutQueueUri() {
        return getURIOrEmpty("BACK_CHANNEL_LOGOUT_QUEUE_URI");
    }

    public String getNotifyTemplateId(String templateName) {
        return env.get(templateName);
    }

    public boolean isTxmaAuditEncodedEnabled() {
        return getFlagOrFalse("TXMA_AUDIT_ENCODED_ENABLED");
    }
}
