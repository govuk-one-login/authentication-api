package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParametersRequest;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterNotFoundException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.pem.PemReader;
import uk.gov.di.authentication.shared.configuration.AuditPublisherConfiguration;
import uk.gov.di.authentication.shared.configuration.BaseLambdaConfiguration;
import uk.gov.di.authentication.shared.helpers.CryptoProviderHelper;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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

    private AWSSimpleSystemsManagement ssmClient;
    private Map<String, String> ssmRedisParameters;
    private Optional<String> passwordPepper;

    private ECPublicKey docAppCredentialSigningPublicKey;

    public ConfigurationService() {}

    ConfigurationService(AWSSimpleSystemsManagement ssmClient) {
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
        return Integer.parseInt(System.getenv().getOrDefault("CODE_MAX_RETRIES_REGISTRATION", "999999"));
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

    public String getDocAppTokenSigningKeyAlias() {
        return System.getenv("DOC_APP_TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getDocAppCriDataEndpoint() {
        return System.getenv("DOC_APP_CRI_DATA_ENDPOINT");
    }

    public String getDocAppAuthEncryptionPublicKey() {
        var paramName = format("{0}-doc-app-public-encryption-key", getEnvironment());
        try {
            var request = new GetParameterRequest().withWithDecryption(true).withName(paramName);
            return getSsmClient().getParameter(request).getParameter().getValue();
        } catch (ParameterNotFoundException e) {
            LOG.error("No parameter exists with name: {}", paramName);
            throw new RuntimeException(e);
        }
    }

    public ECPublicKey getDocAppCredentialSigningPublicKey() {
        if (docAppCredentialSigningPublicKey == null) {
            var paramName = format("{0}-doc-app-public-signing-key", getEnvironment());
            try {
                var request =
                        new GetParameterRequest().withWithDecryption(true).withName(paramName);
                docAppCredentialSigningPublicKey =
                        createECPublicKeyFromPEM(
                                getSsmClient().getParameter(request).getParameter().getValue());
            } catch (ParameterNotFoundException e) {
                LOG.error("No parameter exists with name: {}", paramName);
                throw new RuntimeException(e);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                LOG.error("Error creating public key from parameter: {}", paramName);
                throw new RuntimeException(e);
            }
        }
        return docAppCredentialSigningPublicKey;
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
            var request = new GetParameterRequest().withWithDecryption(true).withName(paramName);
            return getSsmClient().getParameter(request).getParameter().getValue();
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
                new GetParameterRequest()
                        .withWithDecryption(true)
                        .withName(format("{0}-notify-callback-bearer-token", getEnvironment()));

        return getSsmClient().getParameter(request).getParameter().getValue();
    }

    public List<String> getNotifyTestDestinations() {
        var destinations = System.getenv("NOTIFY_TEST_DESTINATIONS");
        return isNull(destinations) || destinations.isBlank()
                ? List.of()
                : Arrays.stream(destinations.split(",")).collect(Collectors.toList());
    }

    public Optional<String> getOidcApiBaseURL() {
        return Optional.ofNullable(System.getenv("OIDC_API_BASE_URL"));
    }

    public Optional<String> getPasswordPepper() {
        if (passwordPepper == null) {
            try {
                var request =
                        new GetParameterRequest()
                                .withWithDecryption(true)
                                .withName(format("{0}-password-pepper", getEnvironment()));
                passwordPepper =
                        Optional.of(getSsmClient().getParameter(request).getParameter().getValue());
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
                    new GetParameterRequest()
                            .withWithDecryption(true)
                            .withName(format("{0}-ipv-capacity", getEnvironment()));
            return Optional.of(getSsmClient().getParameter(request).getParameter().getValue());
        } catch (ParameterNotFoundException e) {
            return Optional.empty();
        }
    }

    private Map<String, String> getSsmRedisParameters() {
        if (ssmRedisParameters == null) {
            var getParametersRequest =
                    new GetParametersRequest()
                            .withNames(
                                    format(
                                            "{0}-{1}-redis-master-host",
                                            getEnvironment(), getRedisKey()),
                                    format(
                                            "{0}-{1}-redis-password",
                                            getEnvironment(), getRedisKey()),
                                    format("{0}-{1}-redis-port", getEnvironment(), getRedisKey()),
                                    format("{0}-{1}-redis-tls", getEnvironment(), getRedisKey()))
                            .withWithDecryption(true);
            var result = getSsmClient().getParameters(getParametersRequest);
            ssmRedisParameters =
                    result.getParameters().stream()
                            .collect(Collectors.toMap(p -> p.getName(), p -> p.getValue()));
        }
        return ssmRedisParameters;
    }

    private AWSSimpleSystemsManagement getSsmClient() {
        if (ssmClient == null) {
            ssmClient =
                    getLocalstackEndpointUri()
                            .map(
                                    l -> {
                                        LOG.info("Localstack endpoint URI is present: " + l);
                                        return AWSSimpleSystemsManagementClient.builder()
                                                .withEndpointConfiguration(
                                                        new AwsClientBuilder.EndpointConfiguration(
                                                                l, getAwsRegion()))
                                                .build();
                                    })
                            .orElseGet(
                                    () -> {
                                        return AWSSimpleSystemsManagementClient.builder()
                                                .withRegion(getAwsRegion())
                                                .build();
                                    });
        }
        return ssmClient;
    }

    private String getRedisKey() {
        return System.getenv("REDIS_KEY");
    }

    private ECPublicKey createECPublicKeyFromPEM(String pem)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (var configReader = new StringReader(pem)) {
            PemReader reader = new PemReader(configReader);
            var keySpec = new X509EncodedKeySpec(reader.readPemObject().getContent());

            return (ECPublicKey)
                    KeyFactory.getInstance("EC", CryptoProviderHelper.bouncyCastle())
                            .generatePublic(keySpec);
        }
    }

    public String getBackChannelLogoutQueueUri() {
        return System.getenv("BACK_CHANNEL_LOGOUT_QUEUE_URI");
    }
}
