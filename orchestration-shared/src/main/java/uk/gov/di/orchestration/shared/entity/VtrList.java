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
    private final CredentialTrustLevelCode tokenCode;
    private final VectorOfTrust effectiveVectorOfTrust;

    public VtrList(List<VectorOfTrust> vtr) {
        validateVtr(vtr);
        this.vtr = !vtr.isEmpty() ? vtr : List.of(VectorOfTrust.DEFAULT_VECTOR_OF_TRUST);
        this.credentialTrustLevel =
                this.vtr.stream()
                        .map(VectorOfTrust::getCredentialTrustLevel)
                        .min(Comparator.naturalOrder())
                        .orElseThrow(); // Should never throw.
        this.levelsOfConfidence =
                this.vtr.stream()
                        .filter(vot -> vot.getCredentialTrustLevel() == this.credentialTrustLevel)
                        .map(VectorOfTrust::getLevelOfConfidence)
                        .distinct()
                        .sorted(Comparator.naturalOrder())
                        .toList();
        this.tokenCode =
                this.vtr.stream()
                        .filter(
                                vot ->
                                        vot.getCredentialTrustLevel()
                                                .equals(this.credentialTrustLevel))
                        .map(VectorOfTrust::getCredentialTrustLevelCode)
                        .findFirst()
                        .orElseThrow(); // Should never throw.
        this.effectiveVectorOfTrust =
                this.vtr.stream()
                        .filter(
                                vot ->
                                        vot.getCredentialTrustLevel()
                                                .equals(this.credentialTrustLevel))
                        .filter(vot -> vot.getLevelOfConfidence().equals(levelsOfConfidence.get(0)))
                        .findFirst()
                        .orElseThrow(); // Should never throw.
    }

    public static VtrList of(VectorOfTrust first, VectorOfTrust... rest) {
        return new VtrList(Stream.concat(Stream.of(first), Arrays.stream(rest)).toList());
    }

    public static VtrList parseFromAuthRequestAttribute(List<String> vtr) {
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
                    return new VtrList(
                            vtrJsonArray.stream()
                                    .map(String.class::cast)
                                    .map(VectorOfTrust::parse)
                                    .toList());
                }
            } catch (net.minidev.json.parser.ParseException
                    | ClassCastException
                    | IllegalArgumentException e) {
                LOG.error("Error when parsing VTR attribute.", e);
                throw new IllegalArgumentException("Invalid VTR attribute.", e);
            }
        }

        LOG.info("VTR attribute is not present. A default value will be used.");
        return DEFAULT_VTR_LIST;
    }

    private static void validateVtr(List<VectorOfTrust> vtr) {
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

    public CredentialTrustLevelCode getTokenCode() {
        return tokenCode;
    }

    public VectorOfTrust getEffectiveVectorOfTrust() {
        return effectiveVectorOfTrust;
    }

    public boolean identityRequired() {
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
