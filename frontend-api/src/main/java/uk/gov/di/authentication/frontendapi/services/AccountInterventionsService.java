package uk.gov.di.authentication.frontendapi.services;

import com.google.gson.JsonParseException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;

import static java.lang.String.format;

public class AccountInterventionsService {

    private static final Logger LOG = LogManager.getLogger(AccountInterventionsService.class);
    private final Json objectMapper = SerializationService.getInstance();

    public AccountInterventionsInboundResponse sendAccountInterventionsOutboundRequest(
            HTTPRequest request) throws UnsuccessfulAccountInterventionsResponseException {

        try {
            LOG.info("Sending account interventions outbound request");
            var response = request.send();
            if (!response.indicatesSuccess()) {
                throw new UnsuccessfulAccountInterventionsResponseException(
                        format(
                                "Error %s when attempting to call Account Interventions outbound endpoint: %s",
                                response.getStatusCode(), response.getContent()),
                        response.getStatusCode());
            }
            LOG.info("Received successful account interventions outbound response");
            return parseResponse(response);
        } catch (IOException e) {
            throw new UnsuccessfulAccountInterventionsResponseException(
                    "Error when attempting to call Account Interventions outbound endpoint", e);
        } catch (ParseException | Json.JsonException | JsonParseException e) {
            throw new UnsuccessfulAccountInterventionsResponseException(
                    "Error parsing HTTP response", e);
        }
    }

    private AccountInterventionsInboundResponse parseResponse(HTTPResponse response)
            throws Json.JsonException, ParseException, JsonParseException {
        return objectMapper.readValue(
                response.getContentAsJSONObject().toString(),
                AccountInterventionsInboundResponse.class,
                true);
    }
}
