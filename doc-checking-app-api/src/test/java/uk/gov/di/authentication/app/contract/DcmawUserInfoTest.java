package uk.gov.di.authentication.app.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.app.services.DocAppCriService;
import uk.gov.di.orchestration.shared.api.DocAppCriAPI;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.CREDENTIAL_JWT;

@PactConsumerTest
public class DcmawUserInfoTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final DocAppCriAPI docAppCriApi = mock(DocAppCriAPI.class);
    private DocAppCriService docAppCriService;
    private Tokens tokens;

    private final String DOC_APP_USER_INFO_PATH = "userinfo/v2";
    private final String DOC_APP_SUBJECT_ID = "dummy-doc-app-subject-id";
    private final String SUB_FIELD = "sub";
    private final String CREDENTIALS_JWT_FIELD = "https://vocab.account.gov.uk/v1/credentialJWT";
    private final String SUB_VALUE = DOC_APP_SUBJECT_ID;
    private final String CREDENTIALS_JWT_VALUE =
            "eyJraWQiOiIwNDEwZTQ0Mi1iNjJiLTQ1YzktOGNkNi00NTE4MGIxNmVmODUiLCJhbGciOiJFUzI1NiJ9.eyAgInN1YiI6ICJkdW1teS1kb2MtYXBwLXN1YmplY3QtaWQiLCAgIm5iZiI6IDQwNzA5MDg4MDAsICAiaXNzIjogImR1bW15RGNtYXdDb21wb25lbnRJZCIsICAiaWF0IjogNDA3MDkwODgwMCwgICJ2YyI6IHsgICAgIkBjb250ZXh0IjogWyAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsICAgICAgImh0dHBzOi8vdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsL2NvbnRleHRzL2lkZW50aXR5LXYxLmpzb25sZCIgICAgXSwgICAgInR5cGUiOiBbICAgICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgICAgICAiQWRkcmVzc0NyZWRlbnRpYWwiICAgIF0sICAgICJjcmVkZW50aWFsU3ViamVjdCI6IHsgICAgfSAgfX0.QjbVNoAGZBFpkuE9RStPi5mAggMvSq0Kio6-EkyDxMJrColmcLPblF0ztgPdF5NEmMEPKst3Ug7AF1gXLW7jxg";
    private final String ERROR_MESSAGE = "error message";

    @BeforeEach
    void setup() {
        docAppCriService = new DocAppCriService(configService, kmsConnectionService, docAppCriApi);
        tokens = new Tokens(new BearerAccessToken("accessToken"), null);
        when(configService.getEnvironment()).thenReturn("not_build");
    }

    @Pact(consumer = "OrchUserInfoConsumer")
    RequestResponsePact validRequestReturnsValidUserInfo(PactDslWithProvider builder) {
        return builder.given("accessToken is a valid access token")
                .given("dummy-doc-app-subject-id is a valid subject")
                .uponReceiving("Valid access token")
                .path("/" + DOC_APP_USER_INFO_PATH)
                .method("POST")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        (body) -> {
                                            body.stringType(SUB_FIELD, SUB_VALUE);
                                            body.minArrayLike(
                                                    CREDENTIALS_JWT_FIELD,
                                                    1,
                                                    PactDslJsonRootValue.stringType(
                                                            CREDENTIALS_JWT_VALUE),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "DcmawCriProvider",
            pactMethod = "validRequestReturnsValidUserInfo",
            pactVersion = PactSpecVersion.V3)
    void getDocAppUserInfoSuccessResponse(MockServer mockServer)
            throws UnsuccessfulCredentialResponseException,
                    ParseException,
                    java.text.ParseException {

        var request =
                new HTTPRequest(
                        POST,
                        ConstructUriHelper.buildURI(mockServer.getUrl(), DOC_APP_USER_INFO_PATH));
        request.setAuthorization(tokens.getAccessToken().toAuthorizationHeader());

        var userInfo = docAppCriService.sendCriDataRequest(request, DOC_APP_SUBJECT_ID);

        assertThat(userInfo, equalTo(getUserInfoFromSuccessfulUserIdentityHttpResponse()));
    }

    @Pact(consumer = "OrchUserInfoConsumer")
    RequestResponsePact invalidAccessTokenReturnsError(PactDslWithProvider builder) {
        return builder.given("accessToken is an invalid access token")
                .given("dummy-doc-app-subject-id is a valid subject")
                .uponReceiving("Invalid access token")
                .path("/" + DOC_APP_USER_INFO_PATH)
                .method("POST")
                .matchHeader(
                        "Authorization",
                        "^(?i)Bearer (.*)(?-i)",
                        tokens.getAccessToken().toAuthorizationHeader())
                .willRespondWith()
                .status(401)
                .body(ERROR_MESSAGE)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "DcmawCriProvider",
            pactMethod = "invalidAccessTokenReturnsError",
            pactVersion = PactSpecVersion.V3)
    void getDocAppUserInfoInvalidAccessTokenErrorResponse(MockServer mockServer) {

        var request =
                new HTTPRequest(
                        POST,
                        ConstructUriHelper.buildURI(mockServer.getUrl(), DOC_APP_USER_INFO_PATH));
        request.setAuthorization(tokens.getAccessToken().toAuthorizationHeader());

        UnsuccessfulCredentialResponseException exception =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> docAppCriService.sendCriDataRequest(request, DOC_APP_SUBJECT_ID));

        assertThat(exception.getHttpCode(), equalTo(401));
        assertThat(
                exception.getMessage(),
                equalTo(
                        "Error 401 when attempting to call CRI data endpoint: "
                                + ERROR_MESSAGE
                                + "\n"));
    }

    private List<String> getUserInfoFromSuccessfulUserIdentityHttpResponse()
            throws ParseException, java.text.ParseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(
                "{"
                        + " \""
                        + SUB_FIELD
                        + "\": \""
                        + SUB_VALUE
                        + "\","
                        + " \""
                        + CREDENTIALS_JWT_FIELD
                        + "\": ["
                        + "     \""
                        + CREDENTIALS_JWT_VALUE
                        + "\""
                        + "]"
                        + "}");
        var contentAsJSONObject = userInfoHTTPResponse.getContentAsJSONObject();
        var serializedSignedJWTs =
                (List<String>) contentAsJSONObject.get(CREDENTIAL_JWT.getValue());
        List<SignedJWT> signedJWTs = new ArrayList<>();
        for (String jwt : serializedSignedJWTs) {
            signedJWTs.add(SignedJWT.parse(jwt));
        }
        return signedJWTs.stream().map(JWSObject::serialize).collect(Collectors.toList());
    }
}
