package uk.gov.di.lambdawarmer.lambda;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvocationType;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.lambda.model.ServiceException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;

import static com.amazonaws.regions.Regions.EU_WEST_2;

public class LambdaWarmerHandler implements RequestHandler<ScheduledEvent, String> {

    private static final Logger LOG = LoggerFactory.getLogger(LambdaWarmerHandler.class);
    private final ConfigurationService configurationService;
    private final AWSLambda awsLambda;

    public LambdaWarmerHandler(ConfigurationService configurationService, AWSLambda awsLambda) {
        this.configurationService = configurationService;
        this.awsLambda = awsLambda;
    }

    public LambdaWarmerHandler() {
        this.configurationService = new ConfigurationService();
        this.awsLambda = AWSLambdaClientBuilder.standard().withRegion(EU_WEST_2).build();
    }

    @Override
    public String handleRequest(ScheduledEvent input, Context context) {
        LOG.info("Lambda warmer started");

        String lambdaArn = configurationService.getLambdaArn();
        int concurrency = configurationService.getMinConcurrency();
        CompletableFuture<InvokeResult>[] invocations = new CompletableFuture[concurrency];
        try {
            for (int i = 0; i < concurrency; i++) {
                invocations[i] = CompletableFuture.supplyAsync(() -> warmLambda(lambdaArn));
                Thread.sleep(75);
            }
        } catch (InterruptedException e) {
            LOG.error("Sleep was interrupted", e);
        }

        CompletableFuture.allOf(invocations).join();

        LOG.info("Lambda warmer finished");
        return "Winter is coming!";
    }

    private InvokeResult warmLambda(String functionName) {
        InvokeRequest invokeRequest =
                new InvokeRequest()
                        .withFunctionName(functionName)
                        .withQualifier(configurationService.getLambdaQualifier())
                        .withPayload("{ \"Hello\": \"World\" }")
                        .withInvocationType(InvocationType.RequestResponse);

        try {
            InvokeResult invokeResult = awsLambda.invoke(invokeRequest);
            LOG.info("Status code: {}", invokeResult.getStatusCode());
            return invokeResult;
        } catch (ServiceException e) {
            LOG.error("Error invoking lambda", e);
            throw new RuntimeException("Error invoking Lambda", e);
        }
    }
}
