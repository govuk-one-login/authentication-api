package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class TxmaAuditHelper {
    public static final String TXMA_AUDIT_ENCODED_HEADER = "txma-audit-encoded";

    public static Optional<String> getTxmaAuditEncodedHeader(APIGatewayProxyRequestEvent request) {
        return getOptionalHeaderValueFromHeaders(
                request.getHeaders(), TXMA_AUDIT_ENCODED_HEADER, false);
    }
}
