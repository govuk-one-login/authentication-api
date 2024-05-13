package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.DeleteMfaMethodRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class DeleteMfaMethodsHandlerTest {

    private static final String EMAIL = "computer-1";
    private static final String CREDENTIAL = "joe.bloggs@test.com";
    private static final String OTP = "123456";
    private final Json objectMapper = SerializationService.getInstance();

    @Test
    void shouldReturn204ForSuccessfulRequest() {
        var handler = new DeleteMfaMethodHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        // MFAMethod mfaMethod = new MFAMethod("1000", "Secondary", "SMS", "Test 1", true);

        DeleteMfaMethodRequest mfaDeleteReq =
                new DeleteMfaMethodRequest("test@domain.co.uk", "12345", "12345");
        try {
            event.setBody(objectMapper.writeValueAsString(getStringObjectMap(mfaDeleteReq)));
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }

        var result = handler.handleRequest(event, context);
        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn400ForInvalidRequest() {

        var handler = new CreateMfaMethodHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }

    private static Map<String, Object> getStringObjectMap(DeleteMfaMethodRequest mfaDelete) {

        Map<String, Object> requestBodyMap = new HashMap<>();
        requestBodyMap.put("email", EMAIL);
        requestBodyMap.put("otp", OTP);
        requestBodyMap.put("mfaIdentifier", mfaDelete.mfaIdentifier());
        return requestBodyMap;
    }
}
