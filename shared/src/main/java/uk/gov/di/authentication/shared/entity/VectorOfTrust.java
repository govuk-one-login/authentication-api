package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;

public class VectorOfTrust {

    private static final Logger LOG = LogManager.getLogger(VectorOfTrust.class);

    @Expose private CredentialTrustLevel credentialTrustLevel;

    @Expose private LevelOfConfidence levelOfConfidence;

    public VectorOfTrust(CredentialTrustLevel credentialTrustLevel) {
        this(credentialTrustLevel, Optional.empty());
    }

    private VectorOfTrust(
            CredentialTrustLevel credentialTrustLevel,
            Optional<LevelOfConfidence> levelOfConfidence) {
        this.credentialTrustLevel = credentialTrustLevel;
        this.levelOfConfidence = levelOfConfidence.orElse(null);
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public LevelOfConfidence getLevelOfConfidence() {
        return levelOfConfidence;
    }

    public boolean containsLevelOfConfidence() {
        return levelOfConfidence != null && !levelOfConfidence.equals(NONE);
    }

    public static VectorOfTrust parseFromAuthRequestAttribute(List<String> vtr) {
        if (isNull(vtr) || vtr.isEmpty()) {
            LOG.info(
                    "VTR attribute is not present so defaulting to {}",
                    CredentialTrustLevel.getDefault().getValue());
            return new VectorOfTrust(CredentialTrustLevel.getDefault());
        }
        JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
        JSONArray vtrJsonArray;
        try {
            // The nimbus package parses the vtr from the auth request as a list with one element
            // which is a json list
            // The .get(0) below returns the json list - it doesn't just get the first element of
            // the Vector of Trust
            vtrJsonArray = (JSONArray) parser.parse(vtr.get(0));
        } catch (net.minidev.json.parser.ParseException | ClassCastException e) {
            LOG.warn("Error when parsing vtr attribute", e);
            throw new IllegalArgumentException("Invalid VTR attribute", e);
        }
        VectorOfTrust vectorOfTrust = parseVtrSet(vtrJsonArray);
        LOG.info("VTR has been processed at vectorOfTrust: {}", vectorOfTrust.toString());

        return vectorOfTrust;
    }

    public static VectorOfTrust getDefaults() {
        return new VectorOfTrust(CredentialTrustLevel.getDefault());
    }

    public String retrieveVectorOfTrustForToken() {
        return credentialTrustLevel.getValue();
    }

    public boolean isValid() {
        return nonNull(getCredentialTrustLevel())
                && !(containsLevelOfConfidence()
                        && Objects.equals(
                                getCredentialTrustLevel(), CredentialTrustLevel.LOW_LEVEL));
    }

    private static VectorOfTrust parseVtrSet(JSONArray vtrJsonArray) {
        return parseVtrStringList(vtrJsonArray.stream().map(Object::toString).toList());
    }

    public static VectorOfTrust parseVtrStringList(List<String> vtrStringArray) {
        if (isNull(vtrStringArray) || vtrStringArray.isEmpty()) {
            LOG.info(
                    "VTR attribute is not present so defaulting to {}",
                    CredentialTrustLevel.getDefault().getValue());
            return new VectorOfTrust(CredentialTrustLevel.getDefault());
        }
        List<VectorOfTrust> vectorOfTrusts = new ArrayList<>();
        for (String vtr : vtrStringArray) {
            var splitVtr = vtr.split("\\.");

            var levelOfConfidence =
                    Arrays.stream(splitVtr)
                            .filter(a -> a.startsWith("P"))
                            .map(LevelOfConfidence::retrieveLevelOfConfidence)
                            .collect(
                                    Collectors.collectingAndThen(
                                            Collectors.toList(),
                                            list -> {
                                                if (list.size() > 1) {
                                                    throw new IllegalArgumentException(
                                                            "VTR must contain either 0 or 1 identity proofing components");
                                                }
                                                return list;
                                            }))
                            .stream()
                            .findFirst();

            var credentialTrustLevel =
                    CredentialTrustLevel.retrieveCredentialTrustLevel(
                            Arrays.stream(splitVtr)
                                    .filter(a -> a.startsWith("C"))
                                    .sorted()
                                    .collect(Collectors.joining(".")));
            var vot = new VectorOfTrust(credentialTrustLevel, levelOfConfidence);
            if (!vot.isValid()) {
                throw new IllegalArgumentException(
                        "P2 identity confidence must require at least Cl.Cm credential trust");
            }
            vectorOfTrusts.add(vot);
        }

        return vectorOfTrusts.stream()
                .filter(vot -> vot.getLevelOfConfidence() != null)
                .min(
                        Comparator.comparing(
                                        VectorOfTrust::getLevelOfConfidence,
                                        Comparator.nullsFirst(Comparator.naturalOrder()))
                                .thenComparing(
                                        VectorOfTrust::getCredentialTrustLevel,
                                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .orElseGet(
                        () ->
                                vectorOfTrusts.stream()
                                        .min(
                                                Comparator.comparing(
                                                        VectorOfTrust::getCredentialTrustLevel,
                                                        Comparator.nullsFirst(
                                                                Comparator.naturalOrder())))
                                        .orElseThrow(
                                                () ->
                                                        new IllegalArgumentException(
                                                                "Invalid VTR attribute")));
    }

    @Override
    public String toString() {
        return "VectorOfTrust{"
                + "credentialTrustLevel="
                + credentialTrustLevel
                + ", levelOfConfidence="
                + levelOfConfidence
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VectorOfTrust that = (VectorOfTrust) o;
        return credentialTrustLevel == that.credentialTrustLevel
                && levelOfConfidence == that.levelOfConfidence;
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialTrustLevel, levelOfConfidence);
    }

    static VectorOfTrust of(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        return new VectorOfTrust(credentialTrustLevel, Optional.ofNullable(levelOfConfidence));
    }
}
