package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.AuthPolicy;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class OrchFrontendAuthorizerHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, AuthPolicy> {

    private static final Logger LOG = LogManager.getLogger(OrchFrontendAuthorizerHandler.class);

    private final ConfigurationService configurationService;

    // IPs below taken from GDS Office and VPN Public IP Addresses:
    // https://sites.google.com/a/digital.cabinet-office.gov.uk/gds/working-at-gds/gds-internal-it/gds-internal-it-network-public-ip-addresses
    private final String[] validIps = {
        "217.196.229.77/32",
        "217.196.229.79/32",
        "217.196.229.80/31",
        "51.149.8.0/25",
        "51.149.8.128/29",
        "3.9.227.33/32",
        "18.132.149.145/32"
    };

    private final SubnetUtils[] subnetUtils =
            Arrays.stream(validIps).map(SubnetUtils::new).toArray(SubnetUtils[]::new);

    public OrchFrontendAuthorizerHandler() {
        this.configurationService = new ConfigurationService();
    }

    public OrchFrontendAuthorizerHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public AuthPolicy handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> orchFrontendAuthorizerHandler(event, context));
    }

    public AuthPolicy orchFrontendAuthorizerHandler(
            APIGatewayProxyRequestEvent event, Context context) {
        LOG.info("Received event in OrchFrontendAuthorizerHandler");

        String principalId = context.getAwsRequestId();
        String environment = configurationService.getEnvironment();
        String ipAddress = event.getRequestContext().getIdentity().getSourceIp();
        if (environment.equals("production")
                || environment.equals("integration")
                || isIp4InCidrs(ipAddress, validIps)) {
            return new AuthPolicy(
                    principalId,
                    AuthPolicy.PolicyDocument.getAllowOnePolicy(
                            configurationService.getAwsRegion(),
                            event.getRequestContext().getAccountId(),
                            event.getRequestContext().getApiId(),
                            event.getRequestContext().getStage(),
                            AuthPolicy.HttpMethod.ALL,
                            "orch-frontend/*"),
                    event.getRequestContext().getAuthorizer());
        }
        throw new RuntimeException("Unauthorized");
    }

    private boolean isIp4InCidrs(String ip) {
        for (SubnetUtils util : subnetUtils) {
            if (util.getInfo().isInRange(ip)) {
                return true;
            }
        }
        return false;
    }
}
