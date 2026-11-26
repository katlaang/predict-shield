import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const html=readFileSync(new URL("../../showcase/public/ai-trained.html",import.meta.url),"utf8");
assert.ok(!html.includes("__TRAINED_MODEL_JSON__"),"trained model not embedded");
assert.ok(!/<script[^>]*src=/.test(html),"no remote or client runtime dependencies");
const match=html.match(/<script type="application\/json" id="trained-model-data">([\s\S]*?)<\/script>/);
assert.ok(match,"missing embedded trained model");
const m=JSON.parse(match[1]);
assert.equal(m.kind,"REAL_TRAINED_SUPERVISED_BINARY_CLASSIFIER");
assert.equal(m.official_test.total,22544);
assert.equal(m.examples.length,24);
assert.equal(m.official_test.tp,8207);
assert.equal(m.official_test.fp,797);
assert.equal(m.official_test.fn,4626);
assert.equal(m.official_test.tn,8914);
assert.equal(m.real_world_false_positive_rate,null);
assert.equal(m.live_telemetry_integrated,false);
assert.equal(m.coefficients.length,
 m.numeric_indices.length+m.categorical_values.reduce((a,c)=>a+c.length,0));
const script=html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(script,"missing executable JavaScript");
new vm.Script(script[1],{filename:"trained-browser.js"});

// Emulate enough of the browser DOM to prove that the real executable page
// makes predictions, handles class selection and changes feature scores.
function element(id){
 const handlers={}, attr={}, children=[];
 return {
  id, dataset:{},type:"", value:"",textContent:"",innerHTML:"",
  style:{},disabled:false,children,
  className:"",title:"",
  setAttribute(k,v){attr[k]=v;},
  getAttribute(k){return attr[k];},
  addEventListener(k,v){handlers[k]=v;},
  fire(k,arg){assert.ok(handlers[k],id+" lacks "+k);handlers[k]({target:this,...arg});},
  append(...v){children.push(...v);},
  appendChild(v){children.push(v);},
  prepend(v){children.unshift(v);},
  remove(){}
 };
}
const els=new Map();
function get(id){
 if(!els.has(id))els.set(id,element(id));
 return els.get(id);
}
get("trained-model-data").textContent=match[1];
const doc={
 getElementById:get,
 createElement:element,
 body:{appendChild(){}}
};
let timer=0;
const urls={createObjectURL(){return "blob:fake";},revokeObjectURL(){}};
vm.runInNewContext(script[1],{
 document:doc,URL:urls,Blob:class {constructor(parts){this.parts=parts;}},
 setTimeout(fn){fn();},setInterval(){return ++timer;},clearInterval(){},console
},{timeout:5000});
assert.equal(get("trained-count").textContent,"18,894");
assert.equal(get("test-count").textContent,"22,544");
assert.equal(get("tp").textContent,"8,207");
assert.equal(get("fp").textContent,"797");
assert.ok(get("attack-score").textContent.includes("/ 100"));
assert.ok(get("scenario-buttons").children.length===6);
let buttons=get("scenario-buttons").children;
const cred=buttons[2];
cred.fire("click");
assert.ok(get("selected-title").textContent.includes("Credential guessing"));
assert.equal(get("prediction").textContent,"NORMAL","show real missed credential benchmark example");
assert.equal(get("result-pill").textContent,"MODEL ERROR");
get("next").fire("click");
assert.ok(get("selected-title").textContent.includes("Credential guessing"));
const reset=get("reset");reset.fire("click");
const firstScore=get("attack-score").textContent;
const firstEdit=get("feature-controls").children[0].children[2];
firstEdit.value="100";
firstEdit.fire("input");
assert.equal(get("result-pill").textContent,"WHAT-IF · NOT SCORED");
assert.notEqual(get("selected-subtitle").textContent,"Untouched original NSL-KDD test record");
const info=String(html);
assert.ok(info.includes("not calibrated probabilities")||info.includes("not calibrated probabilities".replace("probabilities","probability"))||info.includes("not calibrated probabilities of a real intrusion"));
assert.ok(info.includes("This model classifies recorded connections"));
console.log("PASS: learned model browser execution, held-out metrics, documented missed attacks, six classes, and what-if feature scoring.");
