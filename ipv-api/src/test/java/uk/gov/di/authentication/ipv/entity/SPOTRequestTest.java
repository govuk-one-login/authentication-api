package uk.gov.di.authentication.ipv.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SPOTRequestTest {

    private Json objectMapper = SerializationService.getInstance();

    @Test
    void shouldReadSPOTRequestFromJson() throws Json.JsonException {

        String saltString =
                Base64.getEncoder()
                        .encodeToString("Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes());
        String spotRequestJson = buildSpotRequestJson("P2", "/trustmark", saltString);

        SPOTRequest spotRequest = objectMapper.readValue(spotRequestJson, SPOTRequest.class);

        assertNotNull(spotRequest);
        assertEquals(4, spotRequest.getSpotClaims().size());
        assertEquals(
                List.of("<JWT-encoded VC 1>", "<JWT-encoded VC 2>"),
                spotRequest.getSpotClaims().get("https://vocab.account.gov.uk/v1/credentialJWT"));
        assertEquals("P2", spotRequest.getSpotClaims().get("vot"));
        assertEquals("/trustmark", spotRequest.getSpotClaims().get("vtm"));
        assertEquals(saltString, Base64.getEncoder().encodeToString(spotRequest.getSalt()));
        assertEquals("<id>", spotRequest.getLocalAccountId());
        assertEquals("<subject identifier>", spotRequest.getSub());
        assertEquals("<id>", spotRequest.getLogIds().getSessionId());
        assertEquals("<sector id>", spotRequest.getRpSectorId());
    }

    private String buildSpotRequestJson(String vot, String vtm, String saltString) {
        return "{\"in_claims\": {"
                + "     \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                + "         \"<JWT-encoded VC 1>\", "
                + "         \"<JWT-encoded VC 2>\" "
                + "     ],"
                + "     \"vot\": \""
                + vot
                + "\","
                + "     \"vtm\": \""
                + vtm
                + "\", "
                + "     \"http://something/v1/IdentityCredential\": \"<JSON>\""
                + "},"
                + "\"in_local_account_id\": \"<id>\","
                + "\"in_salt\": \""
                + saltString
                + "\","
                + "\"in_rp_sector_id\": \"<sector id>\","
                + "\"out_sub\": \"<subject identifier>\","
                + "\"log_ids\": {"
                + "     \"session_id\": \"<id>\" "
                + "} }";
    }
}
