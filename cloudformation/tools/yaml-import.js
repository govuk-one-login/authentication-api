/**
 * This script pulls together the different parts of the template.yaml SAM file.
 *
 * To build the full stack for real AWS environments run `node yaml-import.js` from the project root
 *
 * To build for local run `node yaml-import.js NO_LOCAL` from the project root
 *
 */

import { Composer, Parser, Scalar, visit, parseDocument } from "yaml";
import { readFileSync, writeFileSync } from "fs";

const globalSkipFlags = process.argv[2] || "";

const sourceFile = readFileSync("../template-source.yaml", "utf8");
const parser = new Parser();

const composer = new Composer();
const [document] = composer.compose(parser.parse(sourceFile));

const visitor = (key, node) => {
  if (node.tag === "!YAMLInclude") {
    const files = node.value.split(",");
    let fullContents;
    files.forEach((fileNameWithFlag) => {
      const [fileName, skipFlag] = fileNameWithFlag.split("#");
      if (!globalSkipFlags.includes(skipFlag)) {
        const file = readFileSync(`./${fileName.trim()}`, "utf8");
        const resources = parseDocument(file).contents.get("Resources", true);
        if (!fullContents) {
          fullContents = resources;
        } else {
          fullContents.items.push(...resources.items);
        }
      }
    });

    return fullContents;
  }

  if (node.tag === "!TextInclude") {
    const file = readFileSync(`./${node.value.trim()}`, "utf8");
    const yamlObject = new Scalar(file);
    return yamlObject;
  }
};
visit(document, visitor);

const outputContent = document.toString();
writeFileSync("../template.yaml", outputContent);
