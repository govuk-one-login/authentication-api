package uk.gov.di.authentication.frontendapi.services;

import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Mock private ConfigurationService configurationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService(configurationService);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(URI.create("http://" + HOST + ":" + PORT));
        when(configurationService.getAccountInterventionServiceCallTimeout()).thenReturn(1000L);
    }

    @Pact(provider = "AccountInterventionsService", consumer = "AuthFrontendAPI")
    public RequestResponsePact getAccountStatusSuccessfully(PactDslWithProvider builder) {
        return builder.given("AIS Server is healthy")
                .uponReceiving("GET Account Status Request")
                .path(AIS_PATH + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(200)
                .body(constructJSONBodySuccessfulRequest())
                .toPact();
    }

    @Pact(provider = "AccountInterventionsService", consumer = "AuthFrontendAPI")
    public RequestResponsePact getAccountStateUnsuccessfully500(PactDslWithProvider builder) {

        return builder.given("AIS Server is unhealthy")
                .uponReceiving("GET Account Status Request")
                .path(AIS_PATH + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(500)
                .body(constructJSONBodyUnsuccessfulRequest())
                .toPact();
    }

    @Pact(provider = "AccountInterventionsService", consumer = "AuthFrontendAPI")
    public RequestResponsePact getAccountStateUnsuccessfully400(PactDslWithProvider builder) {

        return builder.given("AIS Server is healthy")
                .uponReceiving("An invalid GET Account Status Request")
                .path(AIS_PATH)
                .method("GET")
                .willRespondWith()
                .status(400)
                .body(constructJSONBodyUnsuccessfulRequest())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "getAccountStatusSuccessfully")
    void callAISSuccessful() throws UnsuccessfulAccountInterventionsResponseException {
        AccountInterventionsInboundResponse response =
                this.service.sendAccountInterventionsOutboundRequest("aTestUserId");
        System.out.println("200");
        var expectedState = new State(false, false, false, false);
        assertEquals(expectedState, response.state());
    }

    @Test
    @PactTestFor(pactMethod = "getAccountStateUnsuccessfully500")
    void callAISUnsuccessful500() throws UnsuccessfulAccountInterventionsResponseException {
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("aTestUserId"));
        System.out.println("500");

    }

    @Test
    @PactTestFor(pactMethod = "getAccountStateUnsuccessfully400")
    void callAISUnsuccessful400() throws UnsuccessfulAccountInterventionsResponseException {
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest(""));
        System.out.println("400");

    }


    private PactDslJsonBody constructJSONBodySuccessfulRequest(){
        return new PactDslJsonBody()
//                .object("intervention")
//                .numberType("updatedAt")
//                .numberType("appliedAt")
//                .numberType("sentAt")
//                .stringType("description")
//                .numberType("reprovedIdentityAt")
//                .numberType("resetPasswordAt")
//                .closeObject()
                .object("state")
                .booleanType("blocked", false)
                .booleanType("suspended", false)
                .booleanType("reproveIdentity", false)
                .booleanType("resetPassword", false);
    }

    private PactDslJsonBody constructJSONBodyUnsuccessfulRequest(){
        return new PactDslJsonBody()
                .stringType("message");
    }
}
