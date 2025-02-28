package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;

class TxmaAuditHelperTest {
    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TxmaAuditHelper.class);

    @Test
    void checkTxMAAuditEncodedHeaderCanBeExtracted() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        headers.put(TXMA_AUDIT_ENCODED_HEADER, "test");
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.of("test"), result);
    }

    @Test
    void checkTxMAAuditEncodedHeaderOnlyExtractsLowerCase() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        headers.put(TXMA_AUDIT_ENCODED_HEADER.toUpperCase(), "test");
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.empty(), result);
    }

    @Test
    void missingTxMAAuditEncodedHeaderReturnsEmptyOptional() {
        var apiRequest = new APIGatewayProxyRequestEvent();
        var headers = new HashMap<String, String>();
        apiRequest.setHeaders(headers);

        var result = TxmaAuditHelper.getTxmaAuditEncodedHeader(apiRequest);

        assertEquals(Optional.empty(), result);
    }
}
