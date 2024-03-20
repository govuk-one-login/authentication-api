package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.JsonAdapter;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.serialization.VtrListAdapter;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;
import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

/** VTR Request List. */
@JsonAdapter(VtrListAdapter.class)
public class VtrList {

    private static final Logger LOG = LogManager.getLogger(VtrList.class);

    private final List<VectorOfTrust> vtr;
    private final List<VectorOfTrust> selection;

    public VtrList(List<VectorOfTrust> vtr) {
        this.vtr = !vtr.isEmpty() ? vtr : List.of(VectorOfTrust.DEFAULT);
        this.selection = selectMinimal(this.vtr);
    }

    public static VtrList of(VectorOfTrust first, VectorOfTrust... rest) {
        return new VtrList(Stream.concat(Stream.of(first), Arrays.stream(rest)).toList());
    }

    private static List<VectorOfTrust> selectMinimal(List<VectorOfTrust> vtr) {
        Map<LevelOfConfidence.Kind, VectorOfTrust> minimalVotByLocKind =
                vtr.stream()
                        .collect(
                                Collectors.toMap(
                                        (VectorOfTrust vot) -> vot.getLevelOfConfidence().getKind(),
                                        Function.identity(),
                                        (VectorOfTrust first, VectorOfTrust second) ->
                                                first.compareTo(second) <= 0 ? first : second,
                                        LinkedHashMap::new));

        if (minimalVotByLocKind.containsKey(LevelOfConfidence.Kind.NONE)) {
            return List.of(minimalVotByLocKind.get(LevelOfConfidence.Kind.NONE));
        }

        var minAuthComponent =
                minimalVotByLocKind.values().stream()
                        .map(VectorOfTrust::getCredentialTrustLevel)
                        .min(Enum::compareTo)
                        .get();

        return minimalVotByLocKind.values().stream()
                .filter(vot -> vot.getCredentialTrustLevel().equals(minAuthComponent))
                .toList();
    }

    public static VtrList parseFromAuthRequestAttribute(List<String> authRequestVtrAttr) {
        var vtr = parseAuthRequest(authRequestVtrAttr);
        validateVtr(vtr);
        return new VtrList(vtr);
    }

    private static List<VectorOfTrust> parseAuthRequest(List<String> vtr) {
        if (vtr != null && !vtr.isEmpty()) {
            JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
            JSONArray vtrJsonArray;
            try {
                if (vtr.size() != 1) {
                    throw new IllegalArgumentException("Expected VTR to have single entry.");
                }

                // The nimbus package parses the vtr from the auth request as a list with one
                // element
                // which is a json list
                // The .get(0) below returns the json list - it doesn't just get the first element
                // of
                // the Vector of Trust
                vtrJsonArray = (JSONArray) parser.parse(vtr.get(0));
                if (!vtrJsonArray.isEmpty()) {
                    return vtrJsonArray.stream()
                            .map(String.class::cast)
                            .map(VectorOfTrust::parse)
                            .toList();
                }
            } catch (net.minidev.json.parser.ParseException
                    | ClassCastException
                    | IllegalArgumentException e) {
                LOG.error("Error when parsing VTR attribute.", e);
                throw new IllegalArgumentException("Invalid VTR attribute.", e);
            }
        }

        LOG.info(format("VTR attribute is not present. A default value will be used."));
        return Collections.emptyList();
    }

    private static void validateVtr(List<VectorOfTrust> vtr) {
        for (var vot : vtr) {
            validateVot(vot);
        }
    }

    private static void validateVot(VectorOfTrust vot) {
        if (!vot.getCredentialTrustLevel().isSupported()) {
            throw new IllegalArgumentException(
                    format(
                            "Unsupported \"Credential Trust Level\" \"{0}\".",
                            vot.getCredentialTrustLevelCode()));
        }

        if (!vot.getLevelOfConfidence().isSupported()) {
            throw new IllegalArgumentException(
                    format(
                            "Unsupported \"Level of Confidence\" \"{0}\".",
                            vot.getLevelOfConfidenceCode()));
        }
    }

    public List<VectorOfTrust> getVtr() {
        return vtr;
    }

    /**
     * @return The chosen Credential Trust Level. Use if original codes required e.g. Cl vs. C1.
     */
    public CredentialTrustLevelCode getSelectedCredentialTrustLevelCode() {
        return selection.get(0).getCredentialTrustLevelCode();
    }

    /**
     * @return The candidate Levels of Confidence. Use if original codes required i.e. P0 vs. empty.
     */
    public List<LevelOfConfidenceCode> getSelectedLevelOfConfidenceCodes() {
        return selection.stream().map(VectorOfTrust::getLevelOfConfidenceCode).toList();
    }

    /**
     * @return The chosen Credential Trust Level.
     */
    public CredentialTrustLevel getSelectedCredentialTrustLevel() {
        return this.selection.get(0).getCredentialTrustLevel();
    }

    /**
     * @return The candidate Levels of Confidence.
     */
    public List<LevelOfConfidence> getSelectedLevelOfConfidences() {
        return this.selection.stream().map(VectorOfTrust::getLevelOfConfidence).toList();
    }

    /**
     * @return The candidate VoTs from the VTR. If any VoTs don't require identification, then one
     *     with the lowest Credential Trust Level is returned as a singleton. If all require
     *     identification, of those that have the lowest Credential Trust Level, for each kind of
     *     identification (i.g. standard vs hmrc) the ones with the lowest Level of Confidence
     *     are returned.
     */
    public List<VectorOfTrust> getSelection() {
        return this.selection;
    }

    public VectorOfTrust getEffectiveVectorOfTrust() {
        return selection.get(0);
    }

    public boolean identityRequired() {
        return selection.get(0).identityRequired();
    }

    public boolean mfaRequired() {
        return selection.get(0).mfaRequired();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VtrList other) {
            return this.vtr.stream()
                            .map(VectorOfTrust::getCredentialTrustLevelCode)
                            .toList()
                            .equals(
                                    other.vtr.stream()
                                            .map(VectorOfTrust::getCredentialTrustLevelCode)
                                            .toList())
                    && this.vtr.stream()
                            .map(VectorOfTrust::getLevelOfConfidenceCode)
                            .toList()
                            .equals(
                                    other.vtr.stream()
                                            .map(VectorOfTrust::getLevelOfConfidenceCode)
                                            .toList());
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                vtr.stream().map(VectorOfTrust::getCredentialTrustLevelCode).toList(),
                vtr.stream().map(VectorOfTrust::getLevelOfConfidenceCode).toList());
    }
}
