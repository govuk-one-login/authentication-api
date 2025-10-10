const base = {
  parallel: 8,
  format: [
    "html:reports/api-tests-cucumber-report.html",
    "json:reports/api-tests-cucumber-report.json",
  ],
  publish: false,
  retry: 0,
  loader: ["ts-node/esm"],
  import: ["src/steps/**/*.ts", "src/config/**/*.ts"],
};

export default base;

export const codepipeline = {
  ...base,
  retry: 1,
};

export const trafficGeneration = {
  ...base,
  parallel: 3,
};
