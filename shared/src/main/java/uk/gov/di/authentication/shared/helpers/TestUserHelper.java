package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class TestUserHelper {
    private static final Logger LOG = LogManager.getLogger(TestUserHelper.class);
    private static final String TEST_CLIENT_ALLOW_LIST_SECRET_NAME =
            "/%s/test-client-email-allow-list";
    private SecretsManagerClient secretsManagerClient;
    private final ConfigurationService configurationService;
    private SecretCache<List<String>> cachedSecret;
    private final int timeToLiveInSeconds = 300;

    public TestUserHelper(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.secretsManagerClient = getSecretsManagerClient(configurationService);
    }

    public TestUserHelper(
            SecretsManagerClient secretsManagerClient, ConfigurationService configurationService) {
        this.secretsManagerClient = secretsManagerClient;
        this.configurationService = configurationService;
    }

    public boolean isTestJourney(UserContext userContext) {
        return isTestJourney(userContext.getAuthSession().getEmailAddress());
    }

    public boolean isTestJourney(String emailAddress) {
        if (configurationService.isTestClientsEnabled()) {
            LOG.warn("Test journeys are ENABLED");
        } else {
            return false;
        }

        var isTestEmail =
                emailMatchesAllowlist(
                        emailAddress, getEmailAllowListFromSecretsManager(configurationService));

        if (isTestEmail) {
            LOG.info("Is request from a test email address: true");
        }

        return isTestEmail;
    }

    public static boolean emailMatchesAllowlist(String emailAddress, List<String> regexAllowList) {
        if (Objects.isNull(emailAddress)) {
            return false;
        }
        for (String allowedEmailEntry : regexAllowList) {
            try {
                if (allowedEmailEntry.startsWith("^") && allowedEmailEntry.endsWith("$")) {
                    if (Pattern.matches(allowedEmailEntry, emailAddress)) {
                        return true;
                    }
                } else if (Objects.equals(emailAddress, allowedEmailEntry)) {
                    return true;
                }
            } catch (PatternSyntaxException e) {
                LOG.warn("PatternSyntaxException for: {}", allowedEmailEntry);
            }
        }
        return false;
    }

    private List<String> getEmailAllowListFromSecretsManager(
            ConfigurationService configurationService) {
        if (cachedSecret == null || cachedSecret.isExpired()) {
            var request =
                    GetSecretValueRequest.builder()
                            .secretId(
                                    String.format(
                                            TEST_CLIENT_ALLOW_LIST_SECRET_NAME,
                                            configurationService.getEnvironment()));

            GetSecretValueResponse secretValueResponse;
            try {
                secretValueResponse =
                        getSecretsManagerClient(configurationService)
                                .getSecretValue(request.build());
            } catch (Exception e) {
                LOG.error(
                        "Exception when attempting to fetch allow list from secrets manager. Returning empty list.",
                        e);
                return Collections.emptyList();
            }
            var secretString = secretValueResponse.secretString();

            if (secretString == null || secretString.isEmpty()) {
                LOG.warn("Test client allow list secret string is null or empty");
                return Collections.emptyList();
            }
            cachedSecret =
                    new SecretCache<>(
                            Arrays.stream(secretString.split(",")).toList(),
                            NowHelper.nowPlus(timeToLiveInSeconds, ChronoUnit.SECONDS)
                                    .toInstant()
                                    .getEpochSecond());
        }

        return cachedSecret.secret();
    }

    private SecretsManagerClient getSecretsManagerClient(
            ConfigurationService configurationService) {
        if (secretsManagerClient == null) {
            secretsManagerClient =
                    configurationService
                            .getLocalstackEndpointUri()
                            .map(
                                    l -> {
                                        LOG.info("Localstack endpoint URI is present: {}", l);
                                        return SecretsManagerClient.builder()
                                                .region(
                                                        Region.of(
                                                                configurationService
                                                                        .getAwsRegion()))
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
                                            SecretsManagerClient.builder()
                                                    .region(
                                                            Region.of(
                                                                    configurationService
                                                                            .getAwsRegion()))
                                                    .build());
        }
        return secretsManagerClient;
    }

    private record SecretCache<T>(T secret, long timeToLive) {
        boolean isExpired() {
            return NowHelper.now().toInstant().getEpochSecond() > timeToLive;
        }
    }
}
