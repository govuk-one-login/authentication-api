package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Objects;
import java.util.Optional;

public abstract class BaseAuthorizeValidator {

    protected static final String VTR_PARAM = "vtr";
    protected final ConfigurationService configurationService;
    protected final DynamoClientService dynamoClientService;
    protected final IPVCapacityService ipvCapacityService;
    protected static final Logger LOG = LogManager.getLogger(BaseAuthorizeValidator.class);

    protected BaseAuthorizeValidator(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            IPVCapacityService ipvCapacityService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.ipvCapacityService = ipvCapacityService;
    }

    public abstract Optional<AuthRequestError> validate(AuthenticationRequest authRequest)
            throws ClientSignatureValidationException, JwksException;

    ClientRegistry getClientFromDynamo(String clientId) {
        var client = dynamoClientService.getClient(clientId).orElse(null);

        if (Objects.isNull(client)) {
            var errorMsg = "No Client found with given ClientID";
            LOG.warn(errorMsg);
            throw new RuntimeException(errorMsg);
        }
        return client;
    }

    protected void logErrorInProdElseWarn(String logMessage) {
        if (configurationService.getEnvironment().equals("production")) {
            LOG.error(logMessage);
        } else {
            LOG.warn(logMessage);
        }
    }
}
