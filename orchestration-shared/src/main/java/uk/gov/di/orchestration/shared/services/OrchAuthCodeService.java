package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.OrchAuthCodeItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class OrchAuthCodeService extends BaseDynamoService<OrchAuthCodeItem> {
    private static final Logger LOG = LogManager.getLogger(OrchAuthCodeService.class);

    private final long timeToLive;
    private final NowHelper.NowClock nowClock;
    private final Json objectMapper;

    public OrchAuthCodeService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC(), SerializationService.getInstance());
    }

    public OrchAuthCodeService(
            ConfigurationService configurationService, Clock clock, Json objectMapper) {
        super(OrchAuthCodeItem.class, "Orch-Auth-Code", configurationService, true);
        this.timeToLive = configurationService.getAuthCodeExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
        this.objectMapper = objectMapper;
    }

    public OrchAuthCodeService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchAuthCodeItem> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getAuthCodeExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
        this.objectMapper = SerializationService.getInstance();
    }

    // TODO: ATO-1205: Move generation of the authorisation code back into this method (removing the
    // parameter) after consistency checks are complete.
    public AuthorizationCode generateAndSaveAuthorisationCode(
            AuthorizationCode authorizationCode,
            String clientId,
            String clientSessionId,
            String email,
            Long authTime) {
        LOG.info("Generating and saving authorisation code to orch auth code store");

        var exchangeData =
                new AuthCodeExchangeData()
                        .setClientId(clientId)
                        .setClientSessionId(clientSessionId)
                        .setEmail(email)
                        .setAuthTime(authTime);

        var itemTtl = nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS).toInstant().getEpochSecond();

        var authCodeItem =
                new OrchAuthCodeItem()
                        .withAuthCode(authorizationCode.getValue())
                        .withIsUsed(false)
                        .withTimeToLive(itemTtl);

        try {
            var exchangeDataSerialized = objectMapper.writeValueAsString(exchangeData);

            authCodeItem = authCodeItem.withAuthCodeExchangeData(exchangeDataSerialized);
        } catch (JsonException e) {
            logAndThrowOrchAuthCodeException(
                    "Error serializing exchange data for new orch auth code item.", e);
        }

        try {
            put(authCodeItem);
        } catch (Exception e) {
            logAndThrowOrchAuthCodeException("Failed to add Orch auth code item", e);
        }

        return authorizationCode;
    }

    public Optional<AuthCodeExchangeData> getExchangeDataForCode(String code) {
        LOG.info(
                "Retrieving authorisation code exchange data from orch auth code store. Code: {}",
                code);

        Optional<OrchAuthCodeItem> authCodeItem = Optional.empty();

        try {
            authCodeItem = get(code);
        } catch (Exception e) {
            logAndThrowOrchAuthCodeException(
                    String.format("Failed to get orch auth code item. Code: %s", code), e);
        }

        if (authCodeItem.isEmpty()) {
            LOG.info("No orch auth code item found. Code: {}", code);
            return Optional.empty();
        }

        Optional<OrchAuthCodeItem> unusedAuthCodeItem = authCodeItem.filter(c -> !c.getIsUsed());
        if (unusedAuthCodeItem.isEmpty()) {
            LOG.warn("Orch auth code item found with isUsed set to true. Code: {}", code);
            return Optional.empty();
        }

        Optional<OrchAuthCodeItem> validAuthCodeItem =
                unusedAuthCodeItem.filter(
                        c -> c.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        if (validAuthCodeItem.isEmpty()) {
            LOG.info("Orch auth code item with expired TTL found. Code: {}", code);
            return Optional.empty();
        }

        var authCodeExchangeDataSerialized = validAuthCodeItem.get().getAuthCodeExchangeData();

        Optional<AuthCodeExchangeData> authCodeExchangeData = Optional.empty();
        try {
            authCodeExchangeData =
                    Optional.of(
                            objectMapper.readValue(
                                    authCodeExchangeDataSerialized, AuthCodeExchangeData.class));
        } catch (JsonException e) {
            logAndThrowOrchAuthCodeException(
                    String.format(
                            "Error deserializing exchange data for orch auth code item. Code: %s",
                            code),
                    e);
        }

        markAuthCodeAsUsed(authCodeItem.get());

        return authCodeExchangeData;
    }

    private void markAuthCodeAsUsed(OrchAuthCodeItem authCodeItem) {
        var item = authCodeItem.withIsUsed(true);

        try {
            update(item);
        } catch (Exception e) {
            logAndThrowOrchAuthCodeException(
                    String.format(
                            "Failed to mark orch auth code item as used. Code: %s",
                            authCodeItem.getAuthCode()),
                    e);
        }
    }

    private void logAndThrowOrchAuthCodeException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchAuthCodeException(message);
    }
}
