package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class OrchFrontendAuthorizerHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, Map<String, Object>> {

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
    public Map<String, Object> handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> orchFrontendAuthorizerHandler(event, context));
    }

    public Map<String, Object> orchFrontendAuthorizerHandler(
            APIGatewayProxyRequestEvent event, Context context) {
        LOG.info("Received event in OrchFrontendAuthorizerHandler");

        String environment = configurationService.getEnvironment();
        String ipAddress = event.getRequestContext().getIdentity().getSourceIp();

        boolean allowIp =
                environment.equals("production")
                        || environment.equals("integration")
                        || isIp4InCidrs(ipAddress);

        if (!allowIp) {
            throw new RuntimeException("Unauthorized");
        }

        return generatePolicy(
                context.getAwsRequestId(),
                configurationService.getAwsRegion(),
                event.getRequestContext().getAccountId(),
                event.getRequestContext().getApiId(),
                event.getRequestContext().getStage());
    }

    private boolean isIp4InCidrs(String ip) {
        for (SubnetUtils util : subnetUtils) {
            if (util.getInfo().isInRange(ip)) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> generatePolicy(
            String principalId, String region, String accountId, String apiId, String stage) {
        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17");

        Map<String, Object> statement = new HashMap<>();
        statement.put("Action", "execute-api:Invoke");
        statement.put("Effect", "Allow");
        statement.put(
                "Resource",
                String.format(
                        "arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                        region, accountId, apiId, stage, "*", "orch-frontend/*"));
        policyDocument.put("Statement", statement);

        Map<String, Object> policy = new HashMap<>();
        policy.put("principalId", principalId);
        policy.put("policyDocument", policyDocument);

        return policy;
    }
}
