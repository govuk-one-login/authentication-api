package uk.gov.di.helpers;

import java.util.HashMap;
import java.util.Map;

public class RequestBodyHelper {

    public static final Map<String, String> PARSE_REQUEST_BODY(String body) {
        Map<String, String> query_pairs = new HashMap<>();
        String[] splitString = body.split("&");
        for (String pair : splitString) {
            int index = pair.indexOf("=");
            query_pairs.put(pair.substring(0, index), pair.substring(index + 1));
        }
        return query_pairs;
    }
}
