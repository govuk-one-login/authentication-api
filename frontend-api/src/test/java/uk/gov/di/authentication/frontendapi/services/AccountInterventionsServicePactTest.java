package uk.gov.di.authentication.frontendapi.services;

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
import uk.gov.di.authentication.frontendapi.entity.State;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "AccountInterventionsService")
@MockServerConfig(hostInterface = "localhost", port = "8080")
public class AccountInterventionsServicePactTest {
    private AccountInterventionsService service;

    private final String TEST_USER_ID = "aTestUserId";

    private final String HOST = "localhost";

    private final String PORT = "8080";

    private final String AIS_PATH = "/v1/ais/";

    @Mock
    private ConfigurationService configurationService;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService(configurationService);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(URI.create("http://" + HOST + ":" + PORT));
        when(configurationService.getAccountInterventionServiceCallTimeout()).thenReturn(1000L);
    }

    @Pact(provider = "AccountInterventionsService", consumer = "AuthFrontendAPI")
    public RequestResponsePact getAccountStatusSuccessfully(PactDslWithProvider builder){
        String sampleAISResponse = "{\"intervention\":{\"updatedAt\":1696969322935,\"appliedAt\":1696869005821,\"sentAt\":1696869003456,\"description\":\"AIS_USER_PASSWORD_RESET_AND_IDENTITY_REVERIFIED\",\"reprovedIdentityAt\":1696969322935},\"state\":{\"blocked\":true,\"suspended\":false,\"reproveIdentity\":true,\"resetPassword\":false}}";
        return builder.given("AIS Server is healthy")
                .uponReceiving("GET Account Status Request")
                .path(AIS_PATH + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(200)
                .body(sampleAISResponse)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "getAccountStatusSuccessfully")
    void callAIS() throws UnsuccessfulAccountInterventionsResponseException {
        AccountInterventionsInboundResponse response = this.service.sendAccountInterventionsOutboundRequest("aTestUserId");
        var expectedState = new State(true, false, true, false);
        assertEquals(expectedState, response.state());
    }



}