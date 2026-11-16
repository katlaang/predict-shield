// A separate, independent behavior probe: run in its own Node process, not
// inline in the Python orchestrator, so the observation is a fresh process
// boundary rather than a value the orchestrator already computed itself.
//
// Checks two things against whatever minimist version is actually installed
// at <root>/node_modules/minimist:
//   1. The real CVE-2021-44906 / GHSA-xvch-5gv4-984h proof of concept,
//      confirmed against Snyk's own published PoC (SNYK-JS-MINIMIST-2429795):
//      `--_.constructor.constructor.prototype.foo bar` reaches
//      Function.prototype through the `_.constructor.constructor` chain --
//      not the more commonly guessed `--__proto__.y`, which this version
//      already blocks and does not demonstrate the real vulnerability.
//   2. Benign functionality (`--foo bar` -> { foo: 'bar' }) still works.
//
// Usage: node independent_probe.js <root>
const path = require("path");

const root = process.argv[2];
if (!root) {
  console.error("usage: node independent_probe.js <root>");
  process.exit(2);
}

const minimistPath = path.join(root, "node_modules", "minimist");
const minimist = require(minimistPath);
const pkg = require(path.join(minimistPath, "package.json"));

// Real exploit attempt, not a simulated flag: if this version is
// vulnerable, this call itself mutates Function.prototype for the rest of
// this process.
minimist("--_.constructor.constructor.prototype.foo bar".split(" "));
const pollutionObserved = (function () {}).foo === "bar";

const parsed = minimist(["--foo", "bar"]);
const benignFunctionalityWorks = parsed.foo === "bar";

console.log(JSON.stringify({
  observed_package_version: pkg.version,
  pollution_observed: pollutionObserved,
  benign_functionality_works: benignFunctionalityWorks,
}));
