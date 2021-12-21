package uk.gov.di.authentication.sharedtest.helper;

import net.minidev.json.JSONArray;

import java.util.Arrays;

public class JsonArrayHelper {

    public static String jsonArrayOf(String... values) {
        var array = new JSONArray();

        Arrays.stream(values).forEach(array::appendElement);

        return array.toJSONString();
    }
}
