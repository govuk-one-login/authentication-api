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

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static java.util.Objects.isNull;

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
    private Optional<String> passwordPepper;

    public ConfigurationService() {}

    protected ConfigurationService(SsmClient ssmClient) {
        this.ssmClient = ssmClient;
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

    public long getBlockedEmailDuration() {
        return Long.parseLong(System.getenv().getOrDefault("BLOCKED_EMAIL_DURATION", "900"));
    }

    public long getCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("CODE_EXPIRY", "900"));
    }

    public int getCodeMaxRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_MAX_RETRIES", "5"));
    }

    public int getCodeMaxRetriesRegistration() {
        return Integer.parseInt(
                System.getenv().getOrDefault("CODE_MAX_RETRIES_REGISTRATION", "999999"));
    }

    public int getAuthAppCodeWindowLength() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_AUTH_APP_WINDOW_LENGTH", "30"));
    }

    public int getAuthAppCodeAllowedWindows() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_AUTH_APP_ALLOWED_WINDOWS", "9"));
    }

    public String getContactUsLinkRoute() {
        return System.getenv().getOrDefault("CONTACT_US_LINK_ROUTE", "");
    }

    public int getMaxPasswordRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("PASSWORD_MAX_RETRIES", "5"));
    }

    public URI getDefaultLogoutURI() {
        return URI.create(System.getenv("DEFAULT_LOGOUT_URI"));
    }

    public URI getDocAppAuthorisationURI() {
        return URI.create(System.getenv().getOrDefault("DOC_APP_AUTHORISATION_URI", ""));
    }

    public boolean isDocAppApiEnabled() {
        return System.getenv().getOrDefault("DOC_APP_API_ENABLED", "false").equals("true");
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

    public String getDocAppCriDataEndpoint() {
        return System.getenv("DOC_APP_CRI_DATA_ENDPOINT");
    }

    public URI getDocAppDomain() {
        return URI.create(System.getenv("DOC_APP_DOMAIN"));
    }

    public String getDomainName() {
        return System.getenv("DOMAIN_NAME");
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }

    public String getEmailQueueUri() {
        return System.getenv("EMAIL_QUEUE_URL");
    }

    public String getSpotQueueUri() {
        return System.getenv("SPOT_QUEUE_URL");
    }

    public String getFrontendBaseUrl() {
        return System.getenv().getOrDefault("FRONTEND_BASE_URL", "");
    }

    public URI getGovUKAccountsURL() {
        return URI.create(System.getenv().getOrDefault("GOV_UK_ACCOUNTS_URL", ""));
    }

    public boolean getHeadersCaseInsensitive() {
        return System.getenv().getOrDefault("HEADERS_CASE_INSENSITIVE", "false").equals("true");
    }

    public boolean isIdentityEnabled() {
        return System.getenv().getOrDefault("IDENTITY_ENABLED", "false").equals("true");
    }

    public boolean isSpotEnabled() {
        return System.getenv().getOrDefault("SPOT_ENABLED", "false").equals("true");
    }

    public boolean isIdentityTraceLoggingEnabled() {
        return System.getenv()
                .getOrDefault("IDENTITY_TRACE_LOGGING_ENABLED", "false")
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

    public String getIPVSector() {
        return System.getenv("IPV_SECTOR");
    }

    public URI getLoginURI() {
        return URI.create(System.getenv("LOGIN_URI"));
    }

    public String getNotifyApiKey() {
        return System.getenv("NOTIFY_API_KEY");
    }

    public Optional<String> getNotifyApiUrl() {
        return Optional.ofNullable(System.getenv("NOTIFY_URL"));
    }

    public String getNotifyCallbackBearerToken() {
        var request =
                GetParameterRequest.builder()
                        .withDecryption(true)
                        .name(format("{0}-notify-callback-bearer-token", getEnvironment()))
                        .build();

        return getSsmClient().getParameter(request).parameter().value();
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
            if (System.getenv(type.getTemplateName()).equals(templateId)) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
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

    public String getResetPasswordRoute() {
        return System.getenv().getOrDefault("RESET_PASSWORD_ROUTE", "");
    }

    public String getSessionCookieAttributes() {
        return Optional.ofNullable(System.getenv("SESSION_COOKIE_ATTRIBUTES"))
                .orElse("Secure; HttpOnly;");
    }

    public int getSessionCookieMaxAge() {
        return Integer.parseInt(System.getenv().getOrDefault("SESSION_COOKIE_MAX_AGE", "7200"));
    }

    public int getPersistentCookieMaxAge() {
        return Integer.parseInt(
                System.getenv().getOrDefault("PERSISTENT_COOKIE_MAX_AGE", "34190000"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "7200"));
    }

    public String getSmoketestBucketName() {
        return System.getenv("SMOKETEST_SMS_BUCKET_NAME");
    }

    public URI getSkipLoginURI() {
        return URI.create(System.getenv().getOrDefault("SKIP_LOGIN_URI", "http://skip-login"));
    }

    public Optional<String> getSqsEndpointUri() {
        return Optional.ofNullable(System.getenv("SQS_ENDPOINT"));
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

    public boolean isTestClientsEnabled() {
        return System.getenv().getOrDefault("TEST_CLIENTS_ENABLED", "false").equals("true");
    }

    public boolean isResourceIdScopeEnabled() {
        return Boolean.parseBoolean(
                System.getenv().getOrDefault("RESOURCE_ID_SCOPE_ENABLED", "false"));
    }

    public String getTokenSigningKeyAlias() {
        return System.getenv("TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getAuditStorageS3Bucket() {
        return System.getenv("AUDIT_STORAGE_S3_BUCKET");
    }

    public int getWarmupDelayMillis() {
        return Integer.parseInt(System.getenv().getOrDefault("WARMER_DELAY", "75"));
    }

    public String getAuditHmacSecret() {
        return System.getenv("AUDIT_HMAC_SECRET");
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
}
