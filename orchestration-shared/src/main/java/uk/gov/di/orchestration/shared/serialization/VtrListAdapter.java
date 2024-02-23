package uk.gov.di.orchestration.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import software.amazon.awssdk.utils.Lazy;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrRequest;

import java.io.IOException;
import java.util.List;

public class VtrListAdapter extends TypeAdapter<VtrRequest> {

    public static final Lazy<TypeAdapter<List<VectorOfTrust>>> delegateAdaptorProvider =
            new Lazy<>(() -> new Gson().getAdapter(new TypeToken<>() {}));

    @Override
    public void write(JsonWriter jsonWriter, VtrRequest vtrList) throws IOException {
        delegateAdaptorProvider.getValue().write(jsonWriter, vtrList);
    }

    @Override
    public VtrRequest read(JsonReader jsonReader) throws IOException {
        return new VtrRequest(delegateAdaptorProvider.getValue().read(jsonReader));
    }
}
