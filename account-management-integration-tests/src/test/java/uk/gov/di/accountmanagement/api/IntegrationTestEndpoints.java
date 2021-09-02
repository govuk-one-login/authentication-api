package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import uk.gov.di.accountmanagement.helpers.DynamoHelper;
import uk.gov.di.accountmanagement.helpers.RedisHelper;

import java.util.Optional;

public class IntegrationTestEndpoints {
    protected static final String LOCAL_ENDPOINT_FORMAT =
            "http://localhost:45678/restapis/%s/local/_user_request_";
    protected static final String LOCAL_API_GATEWAY_ID =
            Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    public static final String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(String.format(LOCAL_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));

    @BeforeEach
    public void flushData() {
        RedisHelper.flushData();
        DynamoHelper.flushData();
    }
}
