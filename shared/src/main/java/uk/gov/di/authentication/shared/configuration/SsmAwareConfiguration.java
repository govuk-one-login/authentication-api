package uk.gov.di.authentication.shared.configuration;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.client.builder.AwsSyncClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.model.GetParametersRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParametersResult;
import com.amazonaws.services.simplesystemsmanagement.model.Parameter;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterNotFoundException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient.builder;
import static java.util.stream.Collectors.toMap;

public class SsmAwareConfiguration {
    private static final String REGION = System.getenv("AWS_REGION");

    private static final Optional<AWSSimpleSystemsManagement> SSM_CLIENT;

    static {
        if (System.getenv("ENVIRONMENT") == null) {
            SSM_CLIENT = Optional.empty();
        } else if (System.getenv().containsKey("LOCALSTACK_ENDPOINT")) {
            SSM_CLIENT =
                    Optional.ofNullable(System.getenv("LOCALSTACK_ENDPOINT"))
                            .map(l -> new EndpointConfiguration(l, REGION))
                            .map(builder()::withEndpointConfiguration)
                            .map(AwsSyncClientBuilder::build);
        } else {
            SSM_CLIENT = Optional.of(builder().withRegion(REGION).build());
        }
    }

    public static Map<String, String> getParameters(String... names) {
        try {
            var request = new GetParametersRequest().withWithDecryption(true).withNames(names);

            return SSM_CLIENT
                    .map(client -> client.getParameters(request))
                    .map(GetParametersResult::getParameters)
                    .stream()
                    .flatMap(List::stream)
                    .collect(toMap(Parameter::getName, Parameter::getValue));
        } catch (ParameterNotFoundException e) {
            return Collections.emptyMap();
        }
    }
}
