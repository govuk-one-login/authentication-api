package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.clientregistry.services.ManualUpdateClientRegistryValidationService;
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class ManualUpdateClientRegistryHandler
        implements RequestHandler<Object, Map<String, String>> {

    private final ClientService clientService;
    private final ManualUpdateClientRegistryValidationService validationService;
    private final AuditService auditService;
    private final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(ManualUpdateClientRegistryHandler.class);
    private static final String RESULT_KEY = "result";
    private static final String MESSAGE_KEY = "message";
    private static final String RESULT_ERROR = "error";
    private static final String RESULT_SUCCESS = "success";

    public ManualUpdateClientRegistryHandler(
            ClientService clientService,
            ManualUpdateClientRegistryValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public ManualUpdateClientRegistryHandler() {
        this(ConfigurationService.getInstance());
    }

    public ManualUpdateClientRegistryHandler(ConfigurationService configurationService) {
        this.clientService = new DynamoClientService(configurationService);
        this.validationService = new ManualUpdateClientRegistryValidationService();
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public Map<String, String> handleRequest(Object input, Context context) {
        attachTraceId();

        Map<String, String> response = new HashMap<>();

        if (input == null || input.toString().isBlank()) {
            LOG.error("No client config provided");
            return getErrorResponse("No client config provided");
        }

        try {
            var manualUpdateClientRegistryRequest =
                    objectMapper.readValue(
                            input.toString(), ManualUpdateClientRegistryRequest.class);
            var clientId = manualUpdateClientRegistryRequest.clientId();

            LOG.info("Manual update client registry request received");

            if (!clientService.isValidClient(clientId)) {
                LOG.warn("Invalid client id");
                return getErrorResponse("Invalid client id");
            }

            Optional<ErrorObject> errorResponse =
                    validationService.validateManualUpdateClientRegistryRequest(
                            manualUpdateClientRegistryRequest);
            if (errorResponse.isPresent()) {
                LOG.warn(
                        "Failed validation. ErrorCode: {}. ErrorDescription: {}",
                        errorResponse.get().getCode(),
                        errorResponse.get().getDescription());
                return getErrorResponse(
                        String.format(
                                "Failed validation. ErrorCode: %s. ErrorDescription: %s",
                                errorResponse.get().getCode(),
                                errorResponse.get().getDescription()));
            }

            clientService.manualUpdateClient(clientId, manualUpdateClientRegistryRequest);

            LOG.info("Client updated");
            response.put(RESULT_KEY, RESULT_SUCCESS);
            response.put(
                    MESSAGE_KEY,
                    String.format(
                            "Successfully update client with values: %s",
                            manualUpdateClientRegistryRequest.toString()));
            return response;
        } catch (Json.JsonException e) {
            LOG.warn(
                    "Invalid Client registration request. Missing parameters or incorrect type from request");
            return getErrorResponse(
                    "Invalid Client registration request. Missing parameters or incorrect type from request");
        }
    }

    private Map<String, String> getErrorResponse(String errorMessage) {
        Map<String, String> response = new HashMap<>();
        response.put(RESULT_KEY, RESULT_ERROR);
        response.put(MESSAGE_KEY, errorMessage);
        return response;
    }
}
