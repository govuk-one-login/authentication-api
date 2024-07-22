package uk.gov.di.authentication.frontendapi.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.di.authentication.frontendapi.services.ReverificationResultService;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

@PactConsumerTest
class ReverificationTest {
    private final ConfigurationService configService = Mockito.mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService =
            Mockito.mock(KmsConnectionService.class);
    private ReverificationResultService reverificationResultService;
    private Tokens tokens;

    private static final String REVERIFICATION_PATH = "reverification";
    private static final String SUB_FIELD = "sub";
    private static final String SUCCESS_FIELD = "success";
    private static final String ERROR_CODE_FIELD = "error_code";
    private static final String ERROR_DESCRIPTION_FIELD = "error_description";

    private static final String SUB_VALUE = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private static final String ERROR_CODE_VALUE = "IPV_ERR_007";
    private static final String ERROR_DESCRIPTION_VALUE = "errorDescription";

    @BeforeEach
    void setUp() {
        reverificationResultService =
                new ReverificationResultService(configService, kmsConnectionService);
        tokens = new Tokens(new BearerAccessToken("accessToken"), null);
    }

    @Pact(consumer = "AuthReverificationConsumer")
    RequestResponsePact validRequestReturnsSuccessResponse(PactDslWithProvider builder) {
        return builder.given("accessToken is a valid access token")
                .uponReceiving("Valid access token")
                .path("/" + REVERIFICATION_PATH)
                .method("GET")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType(SUB_FIELD, SUB_VALUE);
                                            body.booleanType(SUCCESS_FIELD, true);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IpvCoreBackReverificationProvider",
            pactMethod = "validRequestReturnsSuccessResponse",
            pactVersion = PactSpecVersion.V3)
    void getIPVReverificationSuccessResponse(MockServer mockServer)
            throws ParseException, UnsuccessfulReverificationResponseException {

        var reverificationResponse =
                reverificationResultService.sendIpvReverificationRequest(
                        new UserInfoRequest(
                                ConstructUriHelper.buildURI(
                                        mockServer.getUrl(), REVERIFICATION_PATH),
                                tokens.getBearerAccessToken()));

        assertThat(
                reverificationResponse.getContentAsJSONObject(),
                equalTo(getResponseFromSuccessfulReverification()));
    }

    @Pact(consumer = "AuthReverificationConsumer")
    RequestResponsePact validRequestReturnsFailureResponse(PactDslWithProvider builder) {
        return builder.given("accessToken is a valid access token")
                .uponReceiving("Valid access token")
                .path("/" + REVERIFICATION_PATH)
                .method("GET")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .status(400)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType(SUB_FIELD, SUB_VALUE);
                                            body.booleanType(SUCCESS_FIELD, false);
                                            body.stringType(ERROR_CODE_FIELD, ERROR_CODE_VALUE);
                                            body.stringType(
                                                    ERROR_DESCRIPTION_FIELD,
                                                    ERROR_DESCRIPTION_VALUE);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IpvCoreBackReverificationProvider",
            pactMethod = "validRequestReturnsFailureResponse",
            pactVersion = PactSpecVersion.V3)
    void getIPVReverificationUnsuccessfulResponse(MockServer mockServer) {

        UnsuccessfulReverificationResponseException exception =
                assertThrows(
                        UnsuccessfulReverificationResponseException.class,
                        () -> {
                            reverificationResultService.sendIpvReverificationRequest(
                                    new UserInfoRequest(
                                            ConstructUriHelper.buildURI(
                                                    mockServer.getUrl(), REVERIFICATION_PATH),
                                            tokens.getBearerAccessToken()));
                        });

        assertThat(
                exception.getMessage(),
                equalTo(
                        String.format(
                                "Error 400 when attempting to call IPV reverification endpoint: %s",
                                getResponseFromUnsuccessfulReverification())));
    }

    @Pact(consumer = "AuthReverificationConsumer")
    RequestResponsePact invalidTokenReturnErrorResponse(PactDslWithProvider builder) {
        return builder.given("accessToken is a invalid access token")
                .uponReceiving("Invalid access token")
                .path("/" + REVERIFICATION_PATH)
                .method("GET")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .comment("test")
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "IpvCoreBackReverificationProvider",
            pactMethod = "invalidTokenReturnErrorResponse",
            pactVersion = PactSpecVersion.V3)
    void getIPVUserInfoErrorResponse(MockServer mockServer) {

        UnsuccessfulReverificationResponseException exception =
                assertThrows(
                        UnsuccessfulReverificationResponseException.class,
                        () -> {
                            reverificationResultService.sendIpvReverificationRequest(
                                    new UserInfoRequest(
                                            ConstructUriHelper.buildURI(
                                                    mockServer.getUrl(), REVERIFICATION_PATH),
                                            tokens.getBearerAccessToken()));
                        });

        assertThat(
                exception.getMessage(),
                equalTo("Error 403 when attempting to call IPV reverification endpoint: null"));
    }

    private JSONObject getResponseFromSuccessfulReverification() throws ParseException {
        var reverificationHTTPResponse = new HTTPResponse(200);
        reverificationHTTPResponse.setEntityContentType(APPLICATION_JSON);
        reverificationHTTPResponse.setContent(
                "{"
                        + "\""
                        + SUB_FIELD
                        + "\":\""
                        + SUB_VALUE
                        + "\","
                        + "\""
                        + SUCCESS_FIELD
                        + "\":true"
                        + "}");
        return reverificationHTTPResponse.getContentAsJSONObject();
    }

    private String getResponseFromUnsuccessfulReverification() {
        var reverificationHTTPResponse = new HTTPResponse(400);
        reverificationHTTPResponse.setEntityContentType(APPLICATION_JSON);
        reverificationHTTPResponse.setContent(
                "{"
                        + "\""
                        + ERROR_CODE_FIELD
                        + "\":\""
                        + ERROR_CODE_VALUE
                        + "\","
                        + "\""
                        + ERROR_DESCRIPTION_FIELD
                        + "\":\""
                        + ERROR_DESCRIPTION_VALUE
                        + "\","
                        + "\""
                        + SUB_FIELD
                        + "\":\""
                        + SUB_VALUE
                        + "\","
                        + "\""
                        + SUCCESS_FIELD
                        + "\":false"
                        + "}\n");
        return reverificationHTTPResponse.getContent();
    }
}
