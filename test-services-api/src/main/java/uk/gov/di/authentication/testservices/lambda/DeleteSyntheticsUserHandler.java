package uk.gov.di.authentication.testservices.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.testservices.domain.TestServicesAuditableEvent.AUTH_SYNTHETICS_USER_DELETED;
import static uk.gov.di.authentication.testservices.domain.TestServicesAuditableEvent.AUTH_SYNTHETICS_USER_NOT_FOUND_FOR_DELETION;

public class DeleteSyntheticsUserHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(DeleteSyntheticsUserHandler.class);

    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;

    public DeleteSyntheticsUserHandler() {
        this(ConfigurationService.getInstance());
    }

    public DeleteSyntheticsUserHandler(
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    public DeleteSyntheticsUserHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.configurationService = configurationService;
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        LOG.info("Request received to DeleteSyntheticsUserHandler");

        String email = configurationService.getSyntheticsUsers();
        if (email == null || email.isBlank()) {
            LOG.info("Synthetics user account not configured.");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ACCT_DOES_NOT_EXIST);
        }

        var auditContext =
                AuditContext.emptyAuditContext()
                        .withIpAddress(IpAddressHelper.extractIpAddress(input))
                        .withEmail(email);

        return authenticationService
                .getUserProfileByEmailMaybe(email)
                .map(
                        userProfile -> {
                            authenticationService.removeAccount(userProfile.getEmail());
                            LOG.info("Synthetics user account removed.");

                            auditService.submitAuditEvent(
                                    AUTH_SYNTHETICS_USER_DELETED, auditContext);

                            return generateApiGatewayProxyResponse(204, "");
                        })
                .orElseGet(
                        () -> {
                            LOG.info("Synthetics user account not found.");

                            auditService.submitAuditEvent(
                                    AUTH_SYNTHETICS_USER_NOT_FOUND_FOR_DELETION, auditContext);

                            return generateApiGatewayProxyErrorResponse(
                                    404, ErrorResponse.ACCT_DOES_NOT_EXIST);
                        });
    }
}
