package uk.gov.di.helpers;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

public class RequestBodyHelper {

    public static Map<String, String> PARSE_REQUEST_BODY(String body) {
        Map<String, String> query_pairs = new HashMap<>();

        for (NameValuePair pair : URLEncodedUtils.parse(body, Charset.defaultCharset())) {
            query_pairs.put(pair.getName(), pair.getValue());
        }

        return query_pairs;
    }
}
