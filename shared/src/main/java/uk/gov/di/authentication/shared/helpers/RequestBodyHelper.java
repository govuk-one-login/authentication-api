package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

public class RequestBodyHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequestBodyHelper.class);

    public static Map<String, String> parseRequestBody(String body) {
        Map<String, String> query_pairs = new HashMap<>();

        for (NameValuePair pair : URLEncodedUtils.parse(body, Charset.defaultCharset())) {
            query_pairs.put(pair.getName(), pair.getValue());
        }

        return query_pairs;
    }

    public static void validatePrincipal(
            Subject subjectFromEmail, Map<String, Object> authorizerParams) {
        if (!authorizerParams.containsKey("principalId")) {
            LOGGER.error("principalId is missing");
            throw new RuntimeException("principalId is missing");
        } else if (!subjectFromEmail.getValue().equals(authorizerParams.get("principalId"))) {
            LOGGER.error(
                    "Subject ID: {} does not match principalId: {}",
                    subjectFromEmail,
                    authorizerParams.get("principalId"));
            throw new RuntimeException("Subject ID does not match principalId");
        }
    }
}
