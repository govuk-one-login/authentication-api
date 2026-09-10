/**
 * Replacement for `rain merge` to combine CloudFormation sub-templates.
 *
 * Works entirely at the YAML AST level so all CloudFormation intrinsic
 * function tags (!Sub, !If, !FindInMap, !GetAtt, etc.) are preserved exactly.
 *
 * Replicates Rain's merge behaviour (internal/cmd/merge/util.go):
 *   - AWSTemplateFormatVersion : last file wins
 *   - Description              : concatenated with newline
 *   - Transform                : appended into a sequence
 *   - Metadata                 : deep-merged
 *   - Everything else          : key-merged (Resources, Conditions, Mappings,
 *                                Parameters, Outputs, Globals) —
 *                                clashing keys are a hard error
 *
 * Usage:
 *   node scripts/cfn-merge/merge-templates.js <source-dir> <output-file>
 *
 * Example:
 *   node scripts/cfn-merge/merge-templates.js ci/cloudformation/auth auth-template.yaml
 */

import { parseDocument, YAMLMap, YAMLSeq, Scalar } from "yaml";
import { readFileSync, writeFileSync, readdirSync, statSync } from "fs";
import { join, resolve } from "path";

const [sourceDir, outputFile] = process.argv.slice(2);
if (!sourceDir || !outputFile) {
  console.error("Usage: node merge-templates.js <source-dir> <output-file>");
  process.exit(1);
}

// ── File discovery ────────────────────────────────────────────────────────────

function findYamlFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      results.push(...findYamlFiles(full));
    } else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) {
      results.push(full);
    }
  }
  return results;
}

const allFiles = findYamlFiles(resolve(sourceDir));
const parentFile = allFiles.find((f) => f.endsWith("parent.yaml"));
if (!parentFile) {
  console.error(`No parent.yaml found under ${sourceDir}`);
  process.exit(1);
}
const subFiles = allFiles.filter((f) => f !== parentFile);

// ── AST helpers ───────────────────────────────────────────────────────────────

/** Get a top-level YAMLMap node by key from a document's root YAMLMap */
function getSection(docMap, key) {
  return docMap.get(key, true); // true = return node, not value
}

/** Key-merge srcMap items into dstMap, error on clash */
function keyMergeMap(section, dstMap, srcMap, srcFile) {
  for (const item of srcMap.items) {
    const key = item.key.value ?? item.key;
    if (dstMap.has(key)) {
      throw new Error(
        `Templates have clashing ${section}: ${key} (from ${srcFile})`,
      );
    }
    dstMap.items.push(item);
  }
}

/** Merge a single sub-document's root YAMLMap into the parent's root YAMLMap */
function mergeInto(dstMap, srcMap, srcFile) {
  for (const item of srcMap.items) {
    const key = item.key.value ?? item.key;
    const srcNode = item.value;

    switch (key) {
      case "AWSTemplateFormatVersion":
        // Last wins — overwrite
        dstMap.set(key, srcNode);
        break;

      case "Description": {
        const existing = getSection(dstMap, key);
        if (!existing) {
          dstMap.set(key, srcNode);
        } else {
          const combined = new Scalar(`${existing.value}\n${srcNode.value}`);
          dstMap.set(key, combined);
        }
        break;
      }

      case "Transform": {
        const existing = getSection(dstMap, key);
        if (!existing) {
          dstMap.set(key, srcNode);
        } else {
          // Normalise dst to a sequence
          let seq;
          if (existing instanceof YAMLSeq) {
            seq = existing;
          } else {
            seq = new YAMLSeq();
            seq.items.push(existing);
            dstMap.set(key, seq);
          }
          // Append src (scalar or sequence items)
          if (srcNode instanceof YAMLSeq) {
            seq.items.push(...srcNode.items);
          } else {
            seq.items.push(srcNode);
          }
        }
        break;
      }

      default: {
        // Resources, Conditions, Mappings, Parameters, Outputs, Globals, Metadata, etc.
        const existing = getSection(dstMap, key);
        if (!existing) {
          dstMap.set(key, srcNode);
        } else if (existing instanceof YAMLMap && srcNode instanceof YAMLMap) {
          keyMergeMap(key, existing, srcNode, srcFile);
        } else {
          throw new Error(
            `Cannot merge section "${key}" from ${srcFile}: incompatible node types`,
          );
        }
      }
    }
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

const parentDoc = parseDocument(readFileSync(parentFile, "utf8"), {
  keepSourceTokens: false,
});
const parentMap = parentDoc.contents;

for (const file of subFiles) {
  const doc = parseDocument(readFileSync(file, "utf8"), {
    keepSourceTokens: false,
  });
  if (!doc.contents) continue;
  try {
    mergeInto(parentMap, doc.contents, file);
  } catch (err) {
    console.error(`Error merging ${file}: ${err.message}`);
    process.exit(1);
  }
}

let output = parentDoc.toString();

// Replicate the sed fix from the original merge-templates.sh
output = output.replace(/Mode: OFF/g, 'Mode: "OFF"');

writeFileSync(outputFile, output);
console.log(`Written: ${outputFile}`);
