package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.nonNull;
import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;

public class VectorOfTrustLegacy {

    private static final Logger LOG = LogManager.getLogger(VectorOfTrustLegacy.class);

    @Expose private CredentialTrustLevel credentialTrustLevel;

    @Expose private LevelOfConfidence levelOfConfidence;

    public VectorOfTrustLegacy(CredentialTrustLevel credentialTrustLevel) {
        this(credentialTrustLevel, Optional.empty());
    }

    private VectorOfTrustLegacy(
            CredentialTrustLevel credentialTrustLevel,
            Optional<LevelOfConfidence> levelOfConfidence) {
        this.credentialTrustLevel = credentialTrustLevel;
        this.levelOfConfidence = levelOfConfidence.orElse(null);
    }

    public static <T, U> String format(
            Collection<T> collection, String delimiter, Function<T, U> formatter) {
        return collection.stream()
                .map(formatter)
                .map(U::toString)
                .collect(Collectors.joining(delimiter));
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

    public static List<VectorOfTrustLegacy> parseFromAuthRequestAttribute(List<String> vtr) {
        if (vtr == null || vtr.isEmpty()) {
            LOG.info(
                    "VTR attribute is not present so defaulting to {}",
                    CredentialTrustLevel.getDefault().getValue());
            return List.of(new VectorOfTrustLegacy(CredentialTrustLevel.getDefault()));
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
        List<VectorOfTrustLegacy> vtrList = parseVtrSet(vtrJsonArray);
        String vtrs = stringifyVtrList(vtrList);
        LOG.info("VTR list has been processed as vectorOfTrust list: [{}]", vtrs);
        return vtrList;
    }

    public static CredentialTrustLevel getLowestCredentialTrustLevel(
            List<VectorOfTrustLegacy> vtrList) {
        List<VectorOfTrustLegacy> orderedVtrList = orderVtrList(vtrList);
        if (orderedVtrList.isEmpty()) {
            throw new IllegalArgumentException("Invalid VTR attribute");
        }
        return orderedVtrList.get(0).getCredentialTrustLevel();
    }

    public static List<VectorOfTrustLegacy> orderVtrList(List<VectorOfTrustLegacy> vtrList) {
        return vtrList.stream()
                .sorted(
                        Comparator.comparing(
                                        VectorOfTrustLegacy::getLevelOfConfidence,
                                        Comparator.nullsFirst(Comparator.naturalOrder()))
                                .thenComparing(
                                        VectorOfTrustLegacy::getCredentialTrustLevel,
                                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();
    }

    public static VectorOfTrustLegacy getDefaults() {
        return VectorOfTrustLegacy.of(
                CredentialTrustLevel.getDefault(), LevelOfConfidence.getDefault());
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

    private static List<VectorOfTrustLegacy> parseVtrSet(JSONArray vtrJsonArray) {
        List<VectorOfTrustLegacy> vtrList = new ArrayList<>();
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
            var vot = new VectorOfTrustLegacy(credentialTrustLevel, levelOfConfidence);
            if (!vot.isValid()) {
                throw new IllegalArgumentException(
                        "P2 identity confidence must require at least Cl.Cm credential trust");
            }
            vtrList.add(vot);
        }

        return vtrList;
    }

    public static List<String> getRequestedLevelsOfConfidence(List<VectorOfTrustLegacy> vtrList) {
        return vtrList.stream()
                .map(VectorOfTrustLegacy::getLevelOfConfidence)
                .map(LevelOfConfidence::getValue)
                .toList();
    }

    public static String stringifyVtrList(List<VectorOfTrustLegacy> vtrList) {
        return vtrList.stream().map(VectorOfTrustLegacy::toString).collect(Collectors.joining(","));
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

    public static String stringifyLevelsOfConfidence(List<VectorOfTrustLegacy> votList) {
        return votList.stream()
                .map(VectorOfTrustLegacy::getLevelOfConfidence)
                .map(LevelOfConfidence::getValue)
                .collect(Collectors.joining(","));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VectorOfTrustLegacy that = (VectorOfTrustLegacy) o;
        return credentialTrustLevel == that.credentialTrustLevel
                && levelOfConfidence == that.levelOfConfidence;
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialTrustLevel, levelOfConfidence);
    }

    public static VectorOfTrustLegacy of(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        return new VectorOfTrustLegacy(
                credentialTrustLevel, Optional.ofNullable(levelOfConfidence));
    }
}
