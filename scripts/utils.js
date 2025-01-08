const crypto = require("crypto");

function calculatePairwiseIdentifier(subjectId, sectorId, salt) {
  const hash = crypto
    .createHash("sha256")
    .update(sectorId)
    .update(subjectId)
    .update(salt, "base64")
    .digest("base64");

  return (
    "urn:fdc:gov.uk:2022:" + Buffer.from(hash, "base64").toString("base64url")
  );
}

module.exports = {
  calculatePairwiseIdentifier,
};
