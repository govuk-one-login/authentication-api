package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountdata.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.accountdata.extensions.AuthenticatorExtension;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysRetrieveResponse;
import uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper;
import uk.gov.di.authentication.accountdata.lambda.PasskeysRetrieveHandler;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.SECONDARY_PASSKEY_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class PasskeysRetrieveHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private final ConfigurationService configurationService = ConfigurationService.getInstance();
    DynamoPasskeyService dynamoPasskeyService = new DynamoPasskeyService(configurationService);

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    @BeforeEach
    void setUp() {
        handler = new PasskeysRetrieveHandler(configurationService);
    }

    @Test
    void shouldRetrievePasskeys() {
        // Given
        Map<String, String> headers = new HashMap<>();
        Passkey userPrimaryPasskey =
                PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                        PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
        Passkey userSecondaryPasskey =
                PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                        PUBLIC_SUBJECT_ID, SECONDARY_PASSKEY_ID);
        Passkey anotherUserPasskey =
                PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                        ANOTHER_PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
        dynamoPasskeyService.savePasskeyIfUnique(userPrimaryPasskey);
        dynamoPasskeyService.savePasskeyIfUnique(userSecondaryPasskey);
        dynamoPasskeyService.savePasskeyIfUnique(anotherUserPasskey);

        var expectedResponse =
                new PasskeysRetrieveResponse(
                        List.of(
                                PasskeysRetrieveResponse.from(userPrimaryPasskey),
                                PasskeysRetrieveResponse.from(userSecondaryPasskey)));

        // When
        var response =
                makeRequest(
                        Optional.empty(),
                        headers,
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

        // Then
        assertThat(response.getStatusCode(), equalTo(200));
        assertThat(response, hasJsonBody(expectedResponse));
    }

    @Test
    void shouldReturnEmptyListIfNoPasskeys() {
        // Given
        Map<String, String> headers = new HashMap<>();

        var expectedResponse = new PasskeysRetrieveResponse(Collections.emptyList());

        // When
        var response =
                makeRequest(
                        Optional.empty(),
                        headers,
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

        // Then
        assertThat(response.getStatusCode(), equalTo(200));
        assertThat(response, hasJsonBody(expectedResponse));
    }

    @Test
    void shouldReturn400IfMissingSubjectId() {
        // Given
        Map<String, String> headers = new HashMap<>();

        // When
        var response =
                makeRequest(
                        Optional.empty(),
                        headers,
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", ""));

        // Then
        assertThat(response.getStatusCode(), equalTo(400));
        assertThat(response, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
    }
}
