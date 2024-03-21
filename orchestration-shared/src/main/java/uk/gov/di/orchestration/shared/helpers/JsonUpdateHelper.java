package uk.gov.di.orchestration.shared.helpers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.collections4.SetUtils;

public class JsonUpdateHelper {

    public static String updateJson(String oldJson, String newJson) throws JsonSyntaxException {
        var oldElem = JsonParser.parseString(oldJson);
        var newElem = JsonParser.parseString(newJson);
        var updateElem = update(oldElem, newElem);
        return updateElem.toString();
    }

    private static JsonElement update(JsonElement oldElem, JsonElement newElem) {
        if (oldElem instanceof JsonObject oldObj && newElem instanceof JsonObject newObj) {
            var updatedObj = new JsonObject();
            var oldKeys = oldObj.keySet();
            var newKeys = newObj.keySet();
            var oldOnlyKeys = SetUtils.difference(oldKeys, newKeys);
            var newOnlyKeys = SetUtils.difference(newKeys, oldKeys);
            var updateKeys = SetUtils.intersection(oldKeys, newKeys);

            for (var oldKey : oldOnlyKeys) {
                updatedObj.add(oldKey, oldObj.get(oldKey));
            }

            for (var newKey : newOnlyKeys) {
                updatedObj.add(newKey, newObj.get(newKey));
            }

            for (var updateKey : updateKeys) {
                updatedObj.add(updateKey, update(oldObj.get(updateKey), newObj.get(updateKey)));
            }

            return updatedObj;
        } else if (oldElem instanceof JsonArray oldArr
                && newElem instanceof JsonArray newArr
                && oldArr.size() == newArr.size()) {
            var updatedArr = new JsonArray();

            for (int i = 0; i < oldArr.size(); i++) {
                updatedArr.add(update(oldArr.get(i), newArr.get(i)));
            }

            return updatedArr;
        }

        return newElem;
    }
}
