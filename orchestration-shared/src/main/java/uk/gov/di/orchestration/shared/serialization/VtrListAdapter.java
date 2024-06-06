package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import software.amazon.awssdk.utils.Lazy;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.VtrList;

import java.io.IOException;
import java.util.List;

public class VtrListAdapter extends TypeAdapter<VtrList> {

    public static final Lazy<TypeAdapter<List<VectorOfTrust>>> delegateAdaptorProvider =
            new Lazy<>(() -> new Gson().getAdapter(new TypeToken<>() {}));

    @Override
    public void write(JsonWriter jsonWriter, VtrList vtrList) throws IOException {
        delegateAdaptorProvider.getValue().write(jsonWriter, vtrList.getVtr());
    }

    @Override
    public VtrList read(JsonReader jsonReader) throws IOException {
        return new VtrList(delegateAdaptorProvider.getValue().read(jsonReader));
    }
}
