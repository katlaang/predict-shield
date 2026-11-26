// Run the actual interactive demo's inlined JavaScript with a minimal fake DOM.
// No browser dependencies or network access; tests deterministic scenario state.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
const html = readFileSync(new URL("../public/simulation.html", import.meta.url), "utf8");
assert.ok(html.startsWith("<!doctype html>"));
assert.ok(!/(?:src|href)="https?:\/\//.test(html), "offline simulation must have no remote imports");
assert.match(html, /All events synthetic/);
assert.match(html, /No network access/);
assert.match(html, /NOT a trained PREDICT-SHIELD model output|not a trained model|not a trained PREDICT-SHIELD/i);
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1, "exactly one self-contained script");
const code = scripts[0][1];
new vm.Script(code, {filename:"simulation.inline.js"});

function makeEl(id) {
  const listeners = new Map(), attrs = new Map();
  const el = {
    id, textContent:"", innerHTML:"", disabled:false, value:"",
    dataset:{}, children:[],
    className: {baseVal:"edge"},
    style:{}, classList:{add(){},remove(){}},
    addEventListener(type,cb){listeners.set(type,cb);},
    click(){assert.ok(listeners.has("click"), "missing click handler "+id);listeners.get("click")({});},
    setAttribute(k,v){attrs.set(k,v);},
    getAttribute(k){return attrs.get(k);},
    append(...nodes){this.children.push(...nodes);},
    appendChild(node){this.children.push(node);},
    prepend(node){this.children.unshift(node);},
    remove(){},
  };
  return el;
}
const ids = new Map();
const get = id => { if(!ids.has(id)) ids.set(id,makeEl(id)); return ids.get(id); };
const scenarios = ["ddos","credentials","lateral","unknown","normal"].map(id => {
  const e = makeEl("scenario-"+id);e.dataset.scenario = id;return e;
});
const edges = ["path-ingress","path-app","path-identity","path-db","path-lateral","path-verify"].map(get);
const nodes = ["node-internet","node-edge","node-app","node-identity","node-db","node-workload","node-verifier"].map(get);
const document = {
  getElementById:get,
  querySelectorAll(q){return q===".scenario"?scenarios:q===".edge"?edges:q===".node"?nodes:[];},
  createElement(tag){return makeEl(tag);},
  createTextNode(text){return {textContent:text};},
  body:{appendChild(){}}
};
const timers = new Map();
let nextTimer = 1;
const fakeBlob = class {constructor(content,opts){this.content=content;this.type=opts.type;}};
const url={createObjectURL(){return "blob:fake";},revokeObjectURL(){}};
get("sensitivity").value="50";get("policy").value="balanced";
vm.runInNewContext(code,{
  document, Blob:fakeBlob, URL:url,
  setInterval(cb){const id=nextTimer++;timers.set(id,cb);return id;},
  clearInterval(id){timers.delete(id);},
  setTimeout(cb){cb();},
},{timeout:3000});
function scenario(name) {scenarios.find(s=>s.dataset.scenario===name).click();}
function step(n){for(let i=0;i<n;i++)get("step").click();}
function completeApproved(name,verdict) {
  scenario(name);step(4);
  assert.equal(get("approve").disabled,false,name+" must gate the proposed change");
  assert.match(get("approval").textContent,/PENDING HUMAN/);
  get("approve").click();
  step(2);
  assert.equal(get("step-counter").textContent,"7 / 7");
  assert.equal(get("verification").textContent,verdict);
}
completeApproved("ddos","VERIFIED (simulated)");
completeApproved("credentials","VERIFIED (simulated)");
completeApproved("lateral","ROLLED BACK (simulated)");
assert.equal(get("health").textContent,"Restored");
scenario("unknown");step(7);
assert.equal(get("approve").disabled,true);
assert.equal(get("verification").textContent,"INDETERMINATE");
scenario("normal");step(7);
assert.equal(get("approve").disabled,true);
assert.equal(get("verification").textContent,"No action");
scenario("ddos");step(4);get("deny").click();
assert.equal(get("verification").textContent,"Rejected by operator");
scenario("ddos");get("policy").value="strict";get("policy").addEventListener; 
// select change callback isn't triggered by a click. Dispatch through source control in browser.
assert.ok(code.includes('el("policy").addEventListener("change"'));
assert.ok(code.includes('function exportAudit()'));
assert.ok(code.includes('synthetic:true'));
assert.equal(timers.size,0);
console.log("PASS: all five scenarios, simulated approval/denial, scripted rollback, and no remote assets");
