package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.JsonAdapter;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.serialization.VtrListAdapter;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;
import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

@JsonAdapter(VtrListAdapter.class)
public class VtrList {

    private static final Logger LOG = LogManager.getLogger(VtrList.class);

    public static final VtrList DEFAULT_VTR_LIST = new VtrList(Collections.emptyList());

    private final List<VectorOfTrust> vtr;
    private final CredentialTrustLevel credentialTrustLevel;
    private final List<LevelOfConfidence> levelsOfConfidence;
    private final VectorOfTrust effectiveVectorOfTrust;

    public VtrList(List<VectorOfTrust> vtr) {
        validateVtr(vtr);
        this.vtr = !vtr.isEmpty() ? vtr : List.of(VectorOfTrust.DEFAULT_VECTOR_OF_TRUST);
        this.credentialTrustLevel =
                this.vtr.stream()
                        .map(VectorOfTrust::getCredentialTrustLevel)
                        .min(Comparator.naturalOrder())
                        .orElseThrow();
        this.levelsOfConfidence =
                this.vtr.stream()
                        .map(VectorOfTrust::getLevelOfConfidence)
                        .distinct()
                        .sorted(Comparator.naturalOrder())
                        .toList();
        this.effectiveVectorOfTrust =
                this.vtr.stream()
                        .min(
                                Comparator.comparing(VectorOfTrust::getLevelOfConfidence)
                                        .thenComparing(VectorOfTrust::getCredentialTrustLevel))
                        .orElseThrow();
    }

    /**
     * A VTR must contain at least one element. Use {@link #DEFAULT_VTR_LIST} if you just want a
     * dummy / placeholder value.
     */
    public static VtrList of(VectorOfTrust first, VectorOfTrust... rest) {
        return new VtrList(Stream.concat(Stream.of(first), Arrays.stream(rest)).toList());
    }

    public static VtrList parseFromAuthRequestAttribute(List<String> vtr) {
        if (vtr == null || vtr.isEmpty()) {
            LOG.info("VTR attribute is not present. A default value will be used.");
            return DEFAULT_VTR_LIST;
        }

        try {
            // The nimbus package parses the vtr from the auth request as a list with one element
            // which is a json list
            // The .get(0) below returns the json list - it doesn't just get the first element of
            // the Vector of Trust
            var parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
            var vtrJsonArray = (JSONArray) parser.parse(vtr.get(0));
            return new VtrList(
                    vtrJsonArray.stream()
                            .map(String.class::cast)
                            .map(VectorOfTrust::parse)
                            .toList());
        } catch (net.minidev.json.parser.ParseException | ClassCastException e) {
            LOG.error("Error when parsing VTR attribute.", e);
            throw new IllegalArgumentException("Invalid VTR attribute.", e);
        }
    }

    private static void validateVtr(List<VectorOfTrust> vtr) {
        var locs = vtr.stream().map(VectorOfTrust::getLevelOfConfidence).toList();
        if (locs.stream().anyMatch(loc -> loc.equals(LevelOfConfidence.NONE))
                && !locs.stream().allMatch(loc -> loc.equals(LevelOfConfidence.NONE))) {
            throw new IllegalArgumentException(
                    "VTR cannot contain both identity and non-identity VoTs.");
        }

        for (var vot : vtr) {
            validateVot(vot);
        }
    }

    private static void validateVot(VectorOfTrust vot) {
        if (vot.getLevelOfConfidence() != LevelOfConfidence.NONE
                && vot.getCredentialTrustLevel() == CredentialTrustLevel.LOW_LEVEL) {
            throw new IllegalArgumentException(
                    format(
                            "Unsupported combination of \"Credential Trust Level\": \"{0}\" and \"Level of Confidence\": \"{1}\".",
                            vot.getCredentialTrustLevel(), vot.getLevelOfConfidence()));
        }

        if (!vot.getLevelOfConfidence().isSupported()) {
            throw new IllegalArgumentException(
                    format(
                            "Unsupported \"Level of Confidence\": \"{0}\".",
                            vot.getLevelOfConfidence()));
        }
    }

    public List<VectorOfTrust> getVtr() {
        return vtr;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public List<LevelOfConfidence> getLevelsOfConfidence() {
        return levelsOfConfidence;
    }

    public VectorOfTrust getEffectiveVectorOfTrust() {
        return effectiveVectorOfTrust;
    }

    public boolean identityRequired() {
        // Assumption: Requested vectors of trust will either all be for identity or none, and so we
        // can check just the first
        // This is a safe assumption as we would have rejected the request otherwise
        return levelsOfConfidence.get(0) != LevelOfConfidence.NONE;
    }

    public boolean mfaRequired() {
        return credentialTrustLevel == CredentialTrustLevel.MEDIUM_LEVEL;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VtrList other) {
            return this.vtr.equals(other.vtr);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                vtr.stream().map(VectorOfTrust::getCredentialTrustLevel).toList(),
                vtr.stream().map(VectorOfTrust::getLevelOfConfidence).toList());
    }
}
