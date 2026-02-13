package uk.gov.di.authentication.accountdata.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;

public class PasskeyService {

    private static final Logger LOG = LogManager.getLogger(PasskeyService.class);
    private final SerializationService objectMapper;
    private final DynamoPasskeyService dynamoPasskeyService;
    private final ConfigurationService configurationService;

    public PasskeyService(
            SerializationService objectMapper, ConfigurationService configurationService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
        this.dynamoPasskeyService = new DynamoPasskeyService(configurationService);
    }

    public PasskeyService(
            SerializationService objectMapper,
            ConfigurationService configurationService,
            DynamoPasskeyService dynamoPasskeyService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
        this.dynamoPasskeyService = dynamoPasskeyService;
    }

    public Result<PasskeysCreateFailureReason, Void> createPasskey(
            APIGatewayProxyRequestEvent input) {
        PasskeysCreateRequest passkeysCreateRequest;
        try {
            passkeysCreateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysCreateRequest.class, true);

        } catch (Json.JsonException e) {
            return Result.failure(PasskeysCreateFailureReason.PARSING_PASSKEY_CREATE_REQUEST_ERROR);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(PasskeysCreateFailureReason.REQUEST_MISSING_PARAMS);
        }

        try {
            dynamoPasskeyService.savePasskey(
                    publicSubjectId,
                    passkeysCreateRequest.getPasskeyId(),
                    passkeysCreateRequest.getAaguid(),
                    true, // not sure what isAttested is meant to be
                    0, // not sure what signCount is
                    List.of("SomeTransport"), // not sure transports is
                    true, // not sure what backupEligible is
                    false // not sure what backedUp is
                    );
        } catch (Exception e) {
            LOG.error("Failed to save passkey", e);
            return Result.failure(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY);
        }

        return Result.success(null);
    }
}
