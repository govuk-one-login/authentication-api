package uk.gov.di.orchestration.shared.entity;

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
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;

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
        List<VectorOfTrust> vtrList = parseVtrSet(vtrJsonArray);
        var orderedVtrList = orderVtrList(vtrList);
        LOG.info("VTR has been processed at vectorOfTrust: [{}]", stringifyVtrList(orderedVtrList));

        // Background experiment to ensure no breaking changes are made with removing the existing
        // parsing
        var minimumVtr = orderedVtrList.get(0);
        var existingMinimumVtr = existingGetMinimumVot(vtrList);

        if (minimumVtr.equals(existingMinimumVtr)) {
            return minimumVtr;
        } else {
            LOG.warn("Methods are not equivalent");
            return existingMinimumVtr;
        }
    }

    public static CredentialTrustLevel getLowestCredentialTrustLevel(List<VectorOfTrust> vtrList) {
        List<VectorOfTrust> orderedVtrList = orderVtrList(vtrList);
        if (orderedVtrList.isEmpty()) {
            throw new IllegalArgumentException("Invalid VTR attribute");
        }
        return orderedVtrList.get(0).getCredentialTrustLevel();
    }

    public static List<VectorOfTrust> orderVtrList(List<VectorOfTrust> vtrList) {
        return vtrList.stream()
                .sorted(
                        Comparator.comparing(
                                        VectorOfTrust::getLevelOfConfidence,
                                        Comparator.nullsFirst(Comparator.naturalOrder()))
                                .thenComparing(
                                        VectorOfTrust::getCredentialTrustLevel,
                                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();
    }

    private static VectorOfTrust existingGetMinimumVot(List<VectorOfTrust> vtrList) {
        return vtrList.stream()
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
                                vtrList.stream()
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

    public static VectorOfTrust getDefaults() {
        return VectorOfTrust.of(CredentialTrustLevel.getDefault(), LevelOfConfidence.getDefault());
    }

    public String retrieveVectorOfTrustForToken() {
        return credentialTrustLevel.getValue();
    }

    public boolean isValid() {
        return nonNull(getCredentialTrustLevel())
                && !(Objects.equals(getLevelOfConfidence(), LevelOfConfidence.MEDIUM_LEVEL)
                        && Objects.equals(
                                getCredentialTrustLevel(), CredentialTrustLevel.LOW_LEVEL));
    }

    private static List<VectorOfTrust> parseVtrSet(JSONArray vtrJsonArray) {
        List<VectorOfTrust> vtrList = new ArrayList<>();
        for (Object obj : vtrJsonArray) {
            String vtr = (String) obj;
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
            vtrList.add(vot);
        }

        return vtrList;
    }

    public static List<String> getRequestedLevelsOfConfidence(List<VectorOfTrust> vtrList) {
        return vtrList.stream()
                .map(VectorOfTrust::getLevelOfConfidence)
                .map(LevelOfConfidence::getValue)
                .toList();
    }

    public static String stringifyVtrList(List<VectorOfTrust> vtrList) {
        return vtrList.stream().map(VectorOfTrust::toString).collect(Collectors.joining(","));
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

    public static String stringifyLevelsOfConfidence(List<VectorOfTrust> votList) {
        return votList.stream()
                .map(VectorOfTrust::getLevelOfConfidence)
                .map(LevelOfConfidence::getValue)
                .collect(Collectors.joining(","));
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

    public static VectorOfTrust of(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        return new VectorOfTrust(credentialTrustLevel, Optional.ofNullable(levelOfConfidence));
    }
}
