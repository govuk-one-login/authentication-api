package uk.gov.di.authentication.frontendapi.services;
import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;

import static org.mockito.Mockito.when;
import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.Map;


//@Pact(provider="ArticlesProvider", consumer="test_consumer")
//public RequestResponsePact createPact(PactDslWithProvider builder) {
//    return builder
//            .given("test state")
//            .uponReceiving("ExampleJavaConsumerPactTest test interaction")
//            .path("/articles.json")
//            .method("GET")
//            .willRespondWith()
//            .status(200)
//            .body("{\"responsetest\": true}")
//            .toPact();
//}
@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "test_provider")
@MockServerConfig(hostInterface = "localhost", port = "8080")
public class AccountInterventionsServicePactTest {

    private AccountInterventionsService service;

    @Mock
    private ConfigurationService configurationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService(HttpClient.newHttpClient(), configurationService);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(URI.create("http://localhost:8080"));
        when(configurationService.getAccountInterventionServiceCallTimeout()).thenReturn(1000L);
    }

    @Pact(consumer="test_consumer")
    public RequestResponsePact createPact(PactDslWithProvider builder) {
        System.out.println("setting up pact");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Connection", "[Upgrade, HTTP2-Settings]");
        headers.put("Http2-settings", "[AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA]");
        headers.put("Host", "[localhost:8080]");
        headers.put("User-agent", "[Java-http-client/19.0.2]");
        headers.put("Upgrade", "[h2c]");
        return builder
                .given("AIS Server is healthy")
                    .uponReceiving("GET Account Status Request")
                    .path("/ais/V1/aTestUserId")
                    .method("GET")
                .headers("Connection", "[Upgrade, HTTP2-Settings]", "Http2-settings", "[AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA]")
                .willRespondWith()
                    .status(200)
                    .body("{\"responsetest\": true}")
                .toPact();
    }

    @Test
    @PactTestFor
    protected void runTest(MockServer mockServer) throws IOException, UnsuccessfulAccountInterventionsResponseException {
        AccountInterventionsInboundResponse response = this.service.sendAccountInterventionsOutboundRequest("aTestUserId");
        System.out.println(response);

    }

}