package uk.gov.di.orchestration.local.initialisers;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ClientConfigReader {
    private static final Gson GSON = new GsonBuilder().create();

    private ClientConfigReader() {}

    public static List<ClientRegistry> getClientConfigs() throws IOException {
        var classLoader = ClientConfigReader.class.getClassLoader();

        try (var reader =
                new BufferedReader(
                        new InputStreamReader(
                                classLoader.getResourceAsStream("clients/local-clients.txt"),
                                StandardCharsets.UTF_8))) {
            return reader.lines().map(ClientConfigReader::getClientConfig).toList();
        }
    }

    private static ClientRegistry getClientConfig(String path) {
        var classLoader = ClientConfigReader.class.getClassLoader();

        try (var reader =
                new BufferedReader(
                        new InputStreamReader(
                                classLoader.getResourceAsStream("clients/" + path),
                                StandardCharsets.UTF_8))) {
            return GSON.fromJson(reader, ClientRegistry.class);
        } catch (IOException | JsonParseException e) {
            throw new IllegalArgumentException("Found invalid client config in " + path, e);
        }
    }
}
