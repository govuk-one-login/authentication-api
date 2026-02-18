package uk.gov.di.authentication.accountdata.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;

class PasskeysCreateServiceTest {

    private final DynamoPasskeyService dynamoPasskeyService = mock(DynamoPasskeyService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private PasskeysCreateService passkeysCreateService;

    @BeforeEach
    void setUp() {
        passkeysCreateService =
                new PasskeysCreateService(configurationService, dynamoPasskeyService);
    }

    @Nested
    class CreatePasskey {

        @Nested
        class Success {

            @Test
            void shouldCreatePasskeyGivenValidRequest() {
                // Given
                var createPasskeysRequest =
                        passkeysCreateRequest(
                                format(
                                        """
                            {
                                "credential": "some-credential",
                                "id": "some-id",
                                "aaguid": %s,
                                "attestationSignature": "attestation-signature"
                            }
                        """,
                                        TEST_AAGUID));
                when(dynamoPasskeyService.savePasskeyIfUnique(
                                eq(PUBLIC_SUBJECT_ID),
                                eq("some-id"),
                                eq(TEST_AAGUID),
                                anyBoolean(),
                                anyInt(),
                                anyList(),
                                anyBoolean(),
                                anyBoolean()))
                        .thenReturn(true);

                // When
                var result = passkeysCreateService.createPasskey(createPasskeysRequest);

                // Then
                assertThat(result.isSuccess(), equalTo(true));
            }
        }
    }

    private APIGatewayProxyRequestEvent passkeysCreateRequest(String requestBody) {
        return new APIGatewayProxyRequestEvent()
                .withPathParameters(
                        Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID))
                .withHeaders(CommonTestVariables.VALID_HEADERS)
                .withBody(requestBody)
                .withRequestContext(contextWithSourceIp(CommonTestVariables.IP_ADDRESS));
    }
}
