/**
 * Provenance for the reference skins' colour.
 *
 * The values in `src/skins/skin.ts` are not hand-mixed. They are read from
 * Radix Colors' 12-step scales: step 9 is a solid mark, step 12 is text, and
 * step 3 is a wash to sit content on. Run this to regenerate them and to
 * print the measured contrast against EVERY declared ground:
 *
 *   node scripts/skin-tokens.mjs
 *
 * Two choices here are deliberate departures from the obvious step, both
 * measured rather than judged:
 *
 * - **Light-skin state text is step 12, not step 11.** Radix designs step 11
 *   for text on the scale's own step-1/2 background, and this sheet paints
 *   state ink on washes and on `--surface-inset` too. Measured, step 11 lands
 *   at 4.06-4.46:1 there, under AA, while clearing on white. It was a
 *   guarantee that held only on the one surface anyone checked.
 * - **`--line-strong` is step 10, not step 8 or 9.** It is the only boundary
 *   on buttons, inputs, chips and the segmented control, and WCAG 1.4.11 asks
 *   3:1 for the visual boundary of a user-interface component. Step 8 measured
 *   1.92:1 and step 9 measured 2.95:1 on `--surface-inset`.
 * - **`--focus` is step 11, not step 8.** Step 8 is the border step and
 *   measures 2.33:1 on white, under the 3:1 a focus indicator needs
 *   (WCAG 1.4.11). This file emitted step 8 while `skin.ts` shipped step 11,
 *   so running the documented regeneration would have broken the focus ring.
 *
 * `tests/skin-contract.test.ts` asserts the same thresholds against the same
 * grounds, so a skin cannot regress contrast without failing the suite.
 */
import * as C from "@radix-ui/colors";
const hex=(h)=>{const s=h.replace('#','');const n=parseInt(s.length===3?s.split('').map(c=>c+c).join(''):s,16);return [(n>>16)&255,(n>>8)&255,n&255];};
const lin=(c)=>{c/=255;return c<=0.04045?c/12.92:Math.pow((c+0.055)/1.055,2.4);};
const L=(h)=>{const [r,g,b]=hex(h);return 0.2126*lin(r)+0.7152*lin(g)+0.0722*lin(b);};
const ratio=(a,b)=>{const l1=L(a),l2=L(b);const [hi,lo]=l1>l2?[l1,l2]:[l2,l1];return (hi+0.05)/(lo+0.05);};
const l={
 "--surface-app":C.sage.sage2,"--surface-pane":"#ffffff","--surface-raised":C.sage.sage2,
 "--surface-inset":C.sage.sage3,"--surface-overlay":"#ffffff",
 "--line":C.sage.sage7,"--line-strong":C.sage.sage10,"--focus":C.blue.blue11,
 "--scrim":"rgb(26 33 30 / 0.34)",
 "--ink":C.sage.sage12,"--ink-2":C.sage.sage11,
 "--held-solid":C.grass.grass9,"--held-ink":C.grass.grass12,"--held-wash":C.grass.grass3,
 "--holding-solid":C.amber.amber9,"--holding-ink":C.amber.amber12,"--holding-wash":C.amber.amber3,
 "--broke-solid":C.tomato.tomato9,"--broke-ink":C.tomato.tomato12,"--broke-wash":C.tomato.tomato3,
 "--idle-solid":C.sage.sage9,"--idle-ink":C.sage.sage11,"--idle-wash":C.sage.sage3,
 "--observed-solid":C.tomato.tomato9,"--observed-ink":C.tomato.tomato12,"--observed-wash":C.tomato.tomato3,
 "--reachable-solid":C.amber.amber9,"--reachable-ink":C.amber.amber12,"--reachable-wash":C.amber.amber3,
 "--unknown-solid":C.sage.sage9,"--unknown-ink":C.sage.sage11,"--unknown-wash":C.sage.sage3,
 "--identity-solid":C.blue.blue9,"--identity-ink":C.blue.blue12,"--identity-wash":C.blue.blue3};
const d={
 "--surface-app":C.slateDark.slate1,"--surface-pane":C.slateDark.slate2,"--surface-raised":C.slateDark.slate3,
 "--surface-inset":C.slateDark.slate1,"--surface-overlay":C.slateDark.slate3,
 "--line":C.slateDark.slate6,"--line-strong":C.slateDark.slate9,"--focus":C.blueDark.blue11,
 "--scrim":"rgb(0 0 0 / 0.62)",
 "--ink":C.slateDark.slate12,"--ink-2":C.slateDark.slate11,
 "--held-solid":C.grassDark.grass9,"--held-ink":C.grassDark.grass11,"--held-wash":C.grassDark.grass3,
 "--holding-solid":C.amberDark.amber9,"--holding-ink":C.amberDark.amber11,"--holding-wash":C.amberDark.amber3,
 "--broke-solid":C.tomatoDark.tomato9,"--broke-ink":C.tomatoDark.tomato11,"--broke-wash":C.tomatoDark.tomato3,
 "--idle-solid":C.slateDark.slate9,"--idle-ink":C.slateDark.slate11,"--idle-wash":C.slateDark.slate3,
 "--observed-solid":C.tomatoDark.tomato9,"--observed-ink":C.tomatoDark.tomato11,"--observed-wash":C.tomatoDark.tomato3,
 "--reachable-solid":C.amberDark.amber9,"--reachable-ink":C.amberDark.amber11,"--reachable-wash":C.amberDark.amber3,
 "--unknown-solid":C.slateDark.slate9,"--unknown-ink":C.slateDark.slate11,"--unknown-wash":C.slateDark.slate3,
 "--identity-solid":C.blueDark.blue9,"--identity-ink":C.blueDark.blue11,"--identity-wash":C.blueDark.blue3};
//  A component boundary is a non-text mark: WCAG 1.4.11 asks 3:1.
//  Every ground a token can legally be painted on. Measuring text against
//  `--surface-pane` alone is how six instrument inks shipped under AA: the
//  guarantee was true of the one surface it was checked against.
const GROUNDS=["--surface-pane","--surface-app","--surface-raised","--surface-inset","--surface-overlay"];
let failures=0;
for(const [name,t] of [["instrument",l],["nocturne",d]]){
 console.log(`\n/* ${name} — worst measured contrast, over every declared ground */`);
 for(const k of Object.keys(t).filter(k=>k.endsWith("-ink")||k==="--ink"||k==="--ink-2")){
   //  A state ink also sits on its own wash; a neutral ink never does.
   //  Only a state ink has a wash of its own; "--ink"/"--ink-2" are neutral
   //  and never sit on one. Without this guard the neutral key rewrites to
   //  itself and measures 1.00 against its own value.
   const washKey=/^--[a-z]+-ink$/.test(k)?k.replace(/-ink$/,"-wash"):null;
   const grounds=[...GROUNDS.map(g=>[g,t[g]]),...(washKey&&t[washKey]?[[washKey,t[washKey]]]:[])];
   let worst=[null,Infinity];
   for(const [gn,g] of grounds){const r=ratio(t[k],g); if(r<worst[1]) worst=[gn,r];}
   const bad=worst[1]<4.5; if(bad) failures++;
   console.log(`${bad?"FAIL":"ok  "} ${k.padEnd(18)} ${t[k]}  ${worst[1].toFixed(2)} on ${worst[0]}`);
 }
 //  Non-text indicators: WCAG 1.4.11 asks 3:1, not 4.5:1. `--line-strong` is
 //  the only boundary a button, input, chip or segmented control has.
 for(const k of ["--focus","--line-strong"]) for(const g of GROUNDS){
   const r=ratio(t[k],t[g]);
   if(r<3){failures++; console.log(`FAIL ${k.padEnd(18)} ${t[k]}  ${r.toFixed(2)} on ${g}`);}
 }
 console.log(Object.entries(t).map(([k,v])=>`    "${k}": "${v}",`).join("\n"));
}
if(failures){console.error(`\n${failures} token(s) below their floor.`); process.exitCode=1;}
