package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

public class VectorOfTrust {

    private static final Logger LOG = LogManager.getLogger(VectorOfTrust.class);

    @JsonProperty("credential_trust_level")
    private final CredentialTrustLevel credentialTrustLevel;

    @JsonProperty("level_of_confidence")
    private final LevelOfConfidence levelOfConfidence;

    private VectorOfTrust(CredentialTrustLevel credentialTrustLevel) {
        this(credentialTrustLevel, null);
    }

    @JsonCreator
    private VectorOfTrust(
            @JsonProperty(required = true, value = "credential_trust_level")
                    CredentialTrustLevel credentialTrustLevel,
            @JsonProperty(value = "level_of_confidence") LevelOfConfidence levelOfConfidence) {
        this.credentialTrustLevel = credentialTrustLevel;
        this.levelOfConfidence = levelOfConfidence;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public LevelOfConfidence getLevelOfConfidence() {
        return levelOfConfidence;
    }

    public static VectorOfTrust parseFromAuthRequestAttribute(List<String> vtr) {
        if (Objects.isNull(vtr) || vtr.isEmpty()) {
            LOG.info(
                    "VTR attribute is not present so defaulting to {}",
                    CredentialTrustLevel.getDefault().getValue());
            return new VectorOfTrust(CredentialTrustLevel.getDefault());
        }
        JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
        JSONArray vtrJsonArray;
        try {
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
        if (Objects.isNull(levelOfConfidence)) {
            return credentialTrustLevel.getValue();
        } else {
            return levelOfConfidence.getValue() + "." + credentialTrustLevel.getValue();
        }
    }

    private static VectorOfTrust parseVtrSet(JSONArray vtrJsonArray) {
        List<VectorOfTrust> vectorOfTrusts = new ArrayList<>();
        for (Object obj : vtrJsonArray) {
            String vtr = (String) obj;
            var splitVtr = vtr.split("\\.");

            List<LevelOfConfidence> levelOfConfidence =
                    Arrays.stream(splitVtr)
                            .filter(a -> a.startsWith("P"))
                            .map(LevelOfConfidence::retrieveLevelOfConfidence)
                            .collect(Collectors.toList());
            if (levelOfConfidence.isEmpty()) {
                var ctl = CredentialTrustLevel.retrieveCredentialTrustLevel(vtr);
                vectorOfTrusts.add(new VectorOfTrust(ctl));
            } else {
                var loc = levelOfConfidence.get(0);
                var ctl =
                        CredentialTrustLevel.retrieveCredentialTrustLevel(
                                vtr.substring(vtr.indexOf(".") + 1));
                vectorOfTrusts.add(new VectorOfTrust(ctl, loc));
            }
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
}
