/*
 * For a detailed explanation regarding each configuration property and type check, visit:
 * https://jestjs.io/docs/configuration
 */

import baseConfig from "./jest.config";

export default {
  ...baseConfig,
  coverageReporters: ["json", "lcov"],
  reporters: [
    "github-actions",
    [
      "jest-junit",
      { outputDirectory: "reports/junit", outputName: "jest-test-results.xml" },
    ],
    [
      "jest-silent-reporter",
      { showPaths: true, showWarnings: true, useDots: true },
    ],
    "summary",
  ],
};
