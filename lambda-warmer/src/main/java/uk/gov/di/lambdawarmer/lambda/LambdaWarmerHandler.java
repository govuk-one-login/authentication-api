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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import static com.amazonaws.regions.Regions.EU_WEST_2;
import static java.text.MessageFormat.format;

public class LambdaWarmerHandler implements RequestHandler<ScheduledEvent, String> {

    private static final Logger LOGGER = LogManager.getLogger(LambdaWarmerHandler.class);
    private final ConfigurationService configurationService;
    private final AWSLambda awsLambda;

    public static final String WARMUP_HEADER = "__WARMUP_REQUEST__";

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
        LOGGER.info("Lambda warmer started");

        String lambdaArn = configurationService.getLambdaArn();
        int concurrency = configurationService.getMinConcurrency();
        List<CompletableFuture<InvokeResult>> invocations = new ArrayList<>();
        Executor executor = Executors.newFixedThreadPool(concurrency);
        for (int i = 0; i < concurrency; i++) {
            invocations.add(CompletableFuture.supplyAsync(() -> warmLambda(lambdaArn), executor));
        }

        CompletableFuture.allOf(invocations.toArray(new CompletableFuture[concurrency]))
                .thenRun(
                        () -> {
                            invocations.forEach(
                                    i ->
                                            LOGGER.info(
                                                    "Completed Successfully: {}",
                                                    !i.isCompletedExceptionally()));
                        })
                .join();

        LOGGER.info(
                format(
                        "Lambda warmup for {0}:{1} complete!",
                        lambdaArn, configurationService.getLambdaQualifier()));
        return format(
                "Lambda warmup for {0}:{1} complete!",
                lambdaArn, configurationService.getLambdaQualifier());
    }

    private InvokeResult warmLambda(String functionName) {
        String warmupRequestId = UUID.randomUUID().toString();
        InvokeRequest invokeRequest =
                new InvokeRequest()
                        .withFunctionName(functionName)
                        .withQualifier(configurationService.getLambdaQualifier())
                        .withInvocationType(InvocationType.RequestResponse);
        switch (configurationService.getLambdaType()) {
            case ENDPOINT:
                LOGGER.info("Using ENDPOINT payload");
                invokeRequest.setPayload(
                        format(
                                "'{' \"headers\": '{' \"{0}\": \"{1}\" '}}'",
                                WARMUP_HEADER, warmupRequestId));
                break;
            case AUTHORIZER:
                LOGGER.info("Using AUTHORIZER payload");
                invokeRequest.setPayload(
                        format(
                                "'{' \"type\": \"{0}\", \"authorizationToken\": \"{1}\" '}'",
                                WARMUP_HEADER, warmupRequestId));
                break;
        }
        try {
            LOGGER.info("Invoking warmup request with ID {}", warmupRequestId);
            InvokeResult invokeResult = awsLambda.invoke(invokeRequest);
            return invokeResult;
        } catch (ServiceException e) {
            LOGGER.error("Error invoking lambda");
            throw new RuntimeException("Error invoking Lambda");
        }
    }
}
