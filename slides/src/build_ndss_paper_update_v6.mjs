import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const artifactSearchPaths = (process.env.NODE_PATH || "")
  .split(path.delimiter)
  .filter(Boolean);
let artifactToolPath = null;
for (const root of artifactSearchPaths) {
  const candidate = path.join(root, "@oai", "artifact-tool", "dist", "artifact_tool.mjs");
  try {
    await fs.access(candidate);
    artifactToolPath = candidate;
    break;
  } catch {}
}
if (!artifactToolPath) {
  throw new Error("Set NODE_PATH to the bundled node_modules directory containing @oai/artifact-tool.");
}
const { Presentation, PresentationFile } = await import(pathToFileURL(artifactToolPath).href);

const OUT = path.resolve(process.argv[2] || "slides");
const PREVIEW = path.join(OUT, "preview-v6");
const LAYOUT = path.join(OUT, "layout-v6");
const WEB = path.join(OUT, "web-v6");
const W = 1280;
const H = 720;

const C = {
  ink: "#111418",
  body: "#242A31",
  muted: "#68717D",
  hair: "#D8DEE6",
  pale: "#F4F7FB",
  blue: "#0057FF",
  bluePale: "#EAF1FF",
  green: "#12783A",
  greenPale: "#EAF6EF",
  amber: "#A15C00",
  amberPale: "#FFF5E0",
  red: "#B42318",
  redPale: "#FFF0ED",
  white: "#FFFFFF",
  black: "#000000",
};

const FONT = {
  body: "Microsoft YaHei UI",
  mono: "Cascadia Mono",
};

const slides = [
  {
    no: "01",
    section: "Weekly Thesis",
    title: "RV-MalTrace",
    claim: "What should the group believe after this update?",
    kind: "cover",
    notes: "周会目标：不是复述论文结构，而是让听众能回答研究问题、价值、当前结论、证据、边界和下一步判断。",
  },
  {
    no: "02",
    section: "Six Questions",
    title: "The report has to answer six questions",
    claim: "Every slide should help answer one of them.",
    kind: "sixQuestionMap",
    notes: "把导师/同学带到同一条判断链上：先明确问题和价值，再给结论、证据、边界，最后请大家判断下一步。",
  },
  {
    no: "03",
    section: "Research Problem",
    title: "What is the research problem?",
    claim: "Hardware trace is low-level; malware behavior claims are high-level.",
    kind: "problem",
    notes: "问题不是能不能记录事件，而是能否把低层硬件事件连接到进程、可执行文件和行为标签，同时不把参考日志误报成硬件恢复结果。",
  },
  {
    no: "04",
    section: "Motivation",
    title: "Why is this worth studying?",
    claim: "Software logs are useful references, but they are part of the measured system.",
    kind: "whyMatters",
    notes: "价值要讲清楚：软件 tracing 不是没用，而是不适合单独承担对抗性 workload 的全部证据链；硬件 trace 提供独立观察点，但必须补上归因和边界。",
  },
  {
    no: "05",
    section: "Current Conclusion",
    title: "What is the current core conclusion?",
    claim: "RV-MalTrace supports controlled behavior reconstruction, not detector accuracy.",
    kind: "currentConclusion",
    notes: "当前结论要一句话说完：在受控 RISC-V Linux workload 下，可以从 CVA6/Genesys2 trace 到 source-labeled reconstruction；不能声称真实 malware accuracy。",
  },
  {
    no: "06",
    section: "Evidence Map",
    title: "Which evidence supports the conclusion?",
    claim: "The evidence is useful only if each claim keeps its source and scope.",
    kind: "evidenceMapV6",
    notes: "这页是周会的证据地图：不要先堆图，而是先告诉听众每类证据支持什么，不支持什么。",
  },
  {
    no: "07",
    section: "System Mechanism",
    title: "How does the evidence flow?",
    claim: "Trace records, code maps, runtime maps, and references stay separate.",
    kind: "appPipeline",
    notes: "实现页只服务证据逻辑：哪些字段来自硬件 trace，哪些来自 ELF/runtime map，哪些只是 reference log。",
  },
  {
    no: "08",
    section: "Evidence Detail",
    title: "Evidence 1: trace correctness",
    claim: "The trace contract is tested before semantic claims are made.",
    kind: "eventModel",
    notes: "先证明 trace contract：事件顺序、trap/retire、syscall entry/return、drop accounting。不要直接跳到 malware behavior。",
  },
  {
    no: "09",
    section: "Evidence Detail",
    title: "Evidence 2: source-labeled reconstruction",
    claim: "Derived fields are marked as hardware, ELF, runtime map, or reference.",
    kind: "sourceLabelsV6",
    notes: "回答图表证明了什么：证明 reconstruction 没有把 reference log 当成 hardware output。",
  },
  {
    no: "10",
    section: "Evidence Detail",
    title: "Evidence 3: code attribution",
    claim: "ELF identity, symbols, syscall sites, and runtime maps constrain attribution.",
    kind: "localCode",
    notes: "说明本地 code attribution 支持哪些边界：PIE/ASLR、dynamic object、fork/exec、stripped binary；但不声称 board-native source-line attribution。",
  },
  {
    no: "11",
    section: "Evidence Detail",
    title: "Evidence 4: board runs",
    claim: "122 accepted CVA6 windows support scoped empirical claims.",
    kind: "heroMetric",
    notes: "把 122 作为目前最强的 CVA6 empirical result，同时说明 4 failed retained、0 drops/wraps/gaps in accepted windows。",
  },
  {
    no: "12",
    section: "Evidence Detail",
    title: "Evidence 5: controlled workloads",
    claim: "The workload set checks behavior reconstruction, not real-world coverage.",
    kind: "workloads",
    notes: "明确 workload 的用法：controlled behavior coverage，而不是 in-the-wild malware benchmark。",
  },
  {
    no: "13",
    section: "Evidence Detail",
    title: "Evidence 6: behavior checks",
    claim: "Perfect scoped metrics validate reconstruction, not detector accuracy.",
    kind: "audit",
    notes: "这页必须带红线：1.0/0.0 的指标不能被听众理解成检测器准确率。",
  },
  {
    no: "14",
    section: "Boundary",
    title: "What are the boundaries?",
    claim: "Unsupported topics stay as limitations or future work.",
    kind: "claimBoundary",
    notes: "这页回答证据边界：real malware、production transport、cycle overhead、JTAG RAM boot 不能放进当前主结论。",
  },
  {
    no: "15",
    section: "Alternative Explanations",
    title: "What else could explain the result?",
    claim: "The current evidence rules out some failures, but not all external validity concerns.",
    kind: "alternativesV6",
    notes: "博士周会要主动讲替代解释：是不是 software reference 帮太多？是不是 local fixture 不等于 board evidence？是不是 controlled workload 太窄？",
  },
  {
    no: "16",
    section: "Cost",
    title: "What cost is measured?",
    claim: "Resource and timing evidence support implementation cost, not runtime slowdown.",
    kind: "resources",
    notes: "成本页保留，但必须说清楚：resource delta and timing closure，不是 cycle-level overhead。",
  },
  {
    no: "17",
    section: "Next Step",
    title: "What should the group help decide?",
    claim: "The next work is not more running; it is claim selection and one evidence gap.",
    kind: "nextDecisionV6",
    notes: "最后必须给导师可判断的问题：主 claim 是否足够，是否补一个 board-native evidence，哪些 nonclaims 放 limitations。",
  },
  {
    no: "18",
    section: "Reproducibility",
    title: "The artifact package is reviewable",
    claim: "The paper should cite reproducible evidence, not untracked experiment memory.",
    kind: "repro",
    notes: "reproducibility 不再作为项目管理状态，而是作为证据可信度的一部分。",
  },
  {
    no: "19",
    section: "Takeaway",
    title: "Paper narrative",
    claim: "Problem -> conclusion -> evidence -> boundary -> decision.",
    kind: "paperStory",
    notes: "收尾把六问串起来，不再停在“这周做了哪些事情”。",
  },
  {
    no: "20",
    section: "Appendix",
    title: "Streaming/DMA remains future work",
    claim: "Readiness and target profiles are not throughput evidence.",
    kind: "streaming",
    appendix: true,
    notes: "target p99 0.0215755 B/cycle; required 0.0323633 B/cycle; at 50 MHz required 1.618 MB/s; current sustained=0, noninterference=false。",
  },
  {
    no: "21",
    section: "Appendix",
    title: "Workload roster",
    claim: "Sample names are appendix material, not main-story material.",
    kind: "workloadRoster",
    appendix: true,
    notes: "列出 safe baseline、malware-behavior surrogates、benign controls。长样本名只放在附录，不进入主线叙事。",
  },
  {
    no: "22",
    section: "Appendix",
    title: "Resource detail",
    claim: "Resource/timing claim is supported; runtime overhead is not.",
    kind: "resourceTable",
    appendix: true,
    notes: "baseline vs trace-enabled resource table。",
  },
];

const visualAudit = [
  ["01", "The cover did not state the meeting objective.", "State the expected belief change, not only the project name."],
  ["02", "The talk lacked an explicit checklist.", "Add a six-question map that governs the rest of the deck."],
  ["03", "The research problem could be mistaken for implementation progress.", "Frame the gap between low-level trace and high-level behavior claims."],
  ["04", "Motivation needed a research reason, not just a tool description.", "Explain why software references are insufficient as the only evidence path."],
  ["05", "The conclusion was buried in status pages.", "Make the scoped conclusion explicit before showing evidence."],
  ["06", "Evidence was previously scattered.", "Use one evidence map before detailed results."],
  ["07", "The pipeline page needed to support source separation.", "Show trace, code maps, runtime maps, and reference logs as distinct inputs."],
  ["08", "Trace correctness needed to precede behavior interpretation.", "Make the trace contract the first evidence detail."],
  ["09", "Source labeling needed a dedicated slide.", "Explain that source labels prevent reference logs from becoming hardware claims."],
  ["10", "Code attribution was under-explained.", "Keep edge cases and the missing source-line claim together."],
  ["11", "The strongest empirical result needed visibility.", "Use 122 accepted board windows as the hero evidence."],
  ["12", "Workload scope could imply real-malware benchmarking.", "State controlled workload coverage and its limit."],
  ["13", "Perfect metrics could be misread as detector accuracy.", "Keep the red footer: reconstruction only, not detector accuracy."],
  ["14", "Limitations needed to be part of the argument.", "Treat unsupported topics as claim boundaries."],
  ["15", "Alternative explanations were absent.", "List what the current evidence rules out and what it still cannot rule out."],
  ["16", "Cost evidence risked overclaiming runtime overhead.", "Separate resource/timing closure from cycle-level slowdown."],
  ["17", "The deck lacked a decision request.", "End with concrete group decisions rather than a task list."],
  ["18", "Reproducibility looked like project administration.", "Tie artifact checks to evidence trust."],
  ["19", "The story slide did not mirror the six questions.", "Close with problem, conclusion, evidence, boundary, and decision."],
  ["20", "Streaming/DMA details were dense and easy to misread.", "Keep them as future-work appendix material."],
  ["21", "Sample names are long and can overflow.", "Keep the roster in appendix only."],
  ["22", "Resource table labels can wrap awkwardly.", "Use compact row labels and wider numeric lanes."],
];

const terminologyAudit = [
  ["hardware-rooted", "Replaced", "hardware-assisted", "Hardware-assisted tracing is a standard systems term; hardware-rooted sounded like a slogan."],
  ["trace facts", "Replaced", "trace events / hardware observations", "Trace event is the standard term for records emitted by a tracing system."],
  ["evidence-chain audit", "Replaced", "trace-backed behavior analysis", "The new phrase describes the actual pipeline without inventing a named method."],
  ["lower surface", "Replaced", "out-of-band trace / hardware path", "Out-of-band and sideband are standard trace/monitoring terms."],
  ["evidence planes", "Replaced", "data sources", "Data source is clear and standard; no new abstraction is needed."],
  ["derived rows", "Replaced", "malware-derived behavior cases", "Behavior case is clearer and maps to the repository's case-study evidence."],
  ["No free source lines", "Replaced", "No source-line attribution claim", "Source-line attribution is the standard term."],
  ["P0 safe", "Removed from slides and notes", "safe baseline", "Internal grouping labels do not help the weekly argument."],
  ["oracle", "Explained", "reference/oracle", "Oracle is a standard testing term; main slides use reference for readability."],
  ["provenance", "Moved out of main slide text", "source labels", "Source label is clearer for weekly discussion; provenance remains a standard term if needed in notes."],
  ["surrogate", "Kept and scoped", "safe malware-behavior surrogate", "Surrogate is standard for safety-controlled replacements; notes define it as repo-authored and non-payload."],
];

function line(fill = "none", width = 0) {
  return { style: "solid", fill, width };
}

function rect(slide, x, y, w, h, fill = "none", stroke = "none", width = 0) {
  return slide.shapes.add({
    geometry: "rect",
    position: { left: x, top: y, width: w, height: h },
    fill,
    line: line(stroke, width),
  });
}

function text(slide, value, x, y, w, h, opts = {}) {
  const shape = rect(slide, x, y, w, h, opts.fill || "none", opts.stroke || "none", opts.strokeWidth || 0);
  shape.text = value;
  shape.text.style = {
    fontSize: opts.size ?? 24,
    bold: Boolean(opts.bold),
    color: opts.color || C.body,
    alignment: opts.align || "left",
    typeface: opts.mono ? FONT.mono : FONT.body,
  };
  return shape;
}

function header(slide, s) {
  rect(slide, 0, 0, W, H, C.white);
  rect(slide, 0, 0, 16, H, C.blue);
  text(slide, s.section.toUpperCase(), 72, 40, 420, 24, { size: 13, bold: true, color: C.blue, mono: true });
  text(slide, s.no, 1160, 40, 56, 24, { size: 13, bold: true, color: C.muted, align: "right", mono: true });
  text(slide, s.title, 72, 86, 1040, 58, { size: 36, bold: true, color: C.ink });
  rect(slide, 72, 176, 58, 4, C.blue);
  text(slide, s.claim, 160, 160, 900, 54, { size: 23, bold: true, color: C.body });
}

function notes(slide, s) {
  slide.speakerNotes.textFrame.setText(s.notes);
  slide.speakerNotes.setVisible(true);
}

function cover(slide, s) {
  rect(slide, 0, 0, W, H, C.blue);
  text(slide, "NDSS PAPER UPDATE", 72, 58, 340, 26, { size: 14, bold: true, color: C.white, mono: true });
  text(slide, s.title, 72, 170, 720, 90, { size: 70, bold: true, color: C.white });
  text(slide, s.claim, 78, 294, 820, 50, { size: 27, bold: true, color: C.white });
  rect(slide, 78, 382, 680, 2, C.white);
  text(slide, "Scope: controlled Genesys2/CVA6 tracing and semantic reconstruction. Not a malware detector or production transport claim.", 78, 424, 780, 88, { size: 24, color: C.white });
  text(slide, "artifact root: results/evaluation/genesys2-cva6/current", 78, 650, 680, 22, { size: 13, color: C.white, mono: true });
  rect(slide, 910, 150, 220, 220, C.white);
  text(slide, "TRACE\nEVENTS\nFIRST", 910, 188, 220, 124, { size: 36, bold: true, color: C.blue, align: "center" });
  rect(slide, 910, 420, 210, 30, C.black);
  rect(slide, 910, 478, 150, 30, C.white);
  rect(slide, 910, 536, 185, 30, C.white);
}

function twoColumn(slide, left, right, y = 275) {
  const blocks = [
    [110, left, C.black, C.pale],
    [690, right, C.blue, C.bluePale],
  ];
  for (const [x, b, color, fill] of blocks) {
    rect(slide, x, y, 460, 210, fill, color, 2);
    text(slide, b.kicker, x + 28, y + 28, 360, 26, { size: 15, bold: true, color, mono: true });
    text(slide, b.title, x + 28, y + 74, 360, 42, { size: 28, bold: true, color: C.ink });
    text(slide, b.body, x + 28, y + 132, 380, 44, { size: 19, color: C.muted });
  }
}

function threeBlocks(slide, rows, y = 268) {
  rows.forEach((r, i) => {
    const x = 90 + i * 385;
    rect(slide, x, y, 330, 230, r.fill, r.color, 2);
    text(slide, r.kicker, x + 24, y + 26, 250, 24, { size: 14, bold: true, color: r.color, mono: true });
    text(slide, r.title, x + 24, y + 72, 250, 60, { size: 27, bold: true, color: C.ink });
    text(slide, r.body, x + 24, y + 150, 260, 42, { size: 18, color: C.muted });
  });
}

function rowList(slide, rows, y0 = 265, opts = {}) {
  const step = opts.step ?? 82;
  const labelX = opts.labelX ?? 125;
  const labelW = opts.labelW ?? 145;
  const textX = opts.textX ?? 320;
  const textW = opts.textW ?? 760;
  const textSize = opts.textSize ?? 25;
  const textHeight = opts.textHeight ?? 36;
  const lineOffset = opts.lineOffset ?? 56;
  rows.forEach((r, i) => {
    const y = y0 + i * step;
    rect(slide, labelX, y, labelW, 30, r.color || C.blue);
    text(slide, r.label, labelX, y + 6, labelW, 16, { size: 11, bold: true, color: C.white, align: "center", mono: true });
    text(slide, r.text, textX, y - 2, textW, textHeight, { size: textSize, bold: true, color: C.ink });
    rect(slide, labelX, y + lineOffset, 900, 1, C.hair);
  });
}

function sixQuestionMap(slide) {
  const rows = [
    { label: "Q1", text: "Research problem: low-level trace must support high-level behavior claims", color: C.blue },
    { label: "Q2", text: "Why it matters: software references are visible and must not be the only evidence path", color: C.blue },
    { label: "Q3", text: "Core conclusion: controlled reconstruction works; detector accuracy is not claimed", color: C.green },
    { label: "Q4", text: "Evidence: trace tests, source labels, attribution fixtures, board windows, repro checks", color: C.green },
    { label: "Q5", text: "Boundary: no real-malware accuracy, production transport, or cycle-overhead claim", color: C.amber },
    { label: "Q6", text: "Decision needed: what claim is worth submitting, and which gap to close next?", color: C.red },
  ];
  rowList(slide, rows, 218, { step: 62, labelW: 85, textX: 250, textW: 850, textSize: 19, textHeight: 33, lineOffset: 48 });
}

function whyMatters(slide) {
  threeBlocks(slide, [
    { kicker: "OBSERVATION", title: "Software traces are visible", body: "They are excellent references, but adversarial workloads can observe or react to them.", color: C.blue, fill: C.bluePale },
    { kicker: "INTERPRETATION", title: "Hardware events are not behavior", body: "A PC, trap, or syscall transition still needs process and executable context.", color: C.green, fill: C.greenPale },
    { kicker: "EVIDENCE", title: "Sources can be confused", body: "Reference logs must validate results without being reported as hardware output.", color: C.red, fill: C.redPale },
  ], 260);
}

function currentConclusion(slide) {
  rect(slide, 105, 250, 1070, 120, C.bluePale, C.blue, 2);
  text(slide, "Current conclusion", 138, 275, 270, 24, { size: 16, bold: true, color: C.blue, mono: true });
  text(slide, "For controlled RISC-V Linux workloads, RV-MalTrace can reconstruct behavior summaries from CVA6 trace records while labeling supporting evidence sources.", 138, 315, 980, 42, { size: 25, bold: true, color: C.ink });
  const rows = [
    { label: "SUPPORTED", text: "trace ordering, syscall pairing, source labels, code attribution, reproducibility", color: C.green },
    { label: "NOT CLAIMED", text: "real-malware accuracy, payload equivalence, production throughput, cycle overhead", color: C.red },
  ];
  rowList(slide, rows, 430, { step: 74, textSize: 22, textHeight: 38, lineOffset: 54, textW: 840 });
}

function evidenceMapV6(slide) {
  rowList(slide, [
    { label: "TRACE", text: "Directed tests support event ordering and syscall entry/return pairing", color: C.blue },
    { label: "SOURCE", text: "Reconstruction summaries mark hardware, ELF, runtime-map, and reference fields", color: C.green },
    { label: "ATTRIB.", text: "Local fixtures cover PIE/ASLR, dynamic objects, fork/exec, stripped binaries", color: C.black },
    { label: "BOARD", text: "122 accepted CVA6 windows support scoped empirical claims", color: C.blue },
    { label: "REPRO", text: "Manifest and SHA-256 checks make the current evidence package reviewable", color: C.amber },
  ], 230, { step: 72, labelW: 120, textX: 292, textW: 840, textSize: 20, textHeight: 38, lineOffset: 54 });
}

function sourceLabelsV6(slide) {
  const rows = [
    ["hardware trace", "event sequence, traps, syscall transitions", C.blue],
    ["ELF metadata", "binary identity, sections, symbols", C.green],
    ["runtime map", "process scope and loaded objects", C.black],
    ["reference log", "expected behavior for comparison", C.amber],
  ];
  rows.forEach(([label, body, color], i) => {
    const x = 105 + (i % 2) * 540;
    const y = 262 + Math.floor(i / 2) * 145;
    rect(slide, x, y, 470, 104, i === 3 ? C.amberPale : i === 1 ? C.greenPale : C.pale, color, 2);
    text(slide, label, x + 24, y + 24, 220, 26, { size: 22, bold: true, color, mono: true });
    text(slide, body, x + 24, y + 62, 390, 24, { size: 17, bold: true, color: C.ink });
  });
  text(slide, "The point is not more labels; it is preventing reference evidence from being reported as hardware recovery.", 170, 560, 940, 34, { size: 20, bold: true, color: C.red, align: "center" });
}

function alternativesV6(slide) {
  rowList(slide, [
    { label: "ALT 1", text: "Reference logs may supply too much semantic information; source labels expose that boundary", color: C.amber },
    { label: "ALT 2", text: "Local code-attribution fixtures may not equal board-native source-line evidence", color: C.amber },
    { label: "ALT 3", text: "Controlled workloads may not predict in-the-wild malware behavior coverage", color: C.red },
    { label: "ALT 4", text: "Resource deltas do not establish runtime slowdown without cycle-overhead measurement", color: C.red },
  ], 245, { labelW: 118, textX: 292, textW: 835, textSize: 21, textHeight: 43, lineOffset: 62, step: 82 });
}

function nextDecisionV6(slide) {
  rowList(slide, [
    { label: "DECIDE", text: "Is the submission claim trace-backed behavior reconstruction, not malware detection?", color: C.blue },
    { label: "DECIDE", text: "Which single evidence gap matters most: board-native source lines, overhead, or transport?", color: C.blue },
    { label: "CUT", text: "Move real-malware accuracy and payload-equivalence claims to limitations/future work", color: C.red },
    { label: "NEXT", text: "Convert remaining prose claims into final figures and claim-evidence tables", color: C.green },
  ], 245, { labelW: 118, textX: 292, textW: 840, textSize: 21, textHeight: 42, lineOffset: 62, step: 82 });
}

function problem(slide) {
  twoColumn(slide, {
    kicker: "SOFTWARE OBSERVER",
    title: "Rich semantics",
    body: "Useful reference data, but visible to the workload.",
  }, {
    kicker: "OUT-OF-BAND TRACE",
    title: "Hardware path",
    body: "Commit-time trace starts below user-mode observer checks.",
  });
}

function thesis(slide) {
  text(slide, "TRACE EVENTS", 110, 282, 420, 58, { size: 47, bold: true, color: C.blue, mono: true });
  text(slide, "with", 560, 292, 120, 44, { size: 30, bold: true, color: C.muted, align: "center" });
  text(slide, "PROVENANCE", 720, 282, 430, 58, { size: 46, bold: true, color: C.green, mono: true });
  rect(slide, 120, 380, 1040, 2, C.hair);
  text(slide, "Committed events are hardware observations.", 140, 430, 430, 40, { size: 24, bold: true, color: C.ink });
  text(slide, "Provenance means source tags for derived labels.", 715, 430, 430, 50, { size: 23, bold: true, color: C.ink });
}

function contrib(slide) {
  threeBlocks(slide, [
    { kicker: "C1", title: "CVA6 trace tap", body: "Out-of-band commit, privilege, and drop events.", color: C.blue, fill: C.bluePale },
    { kicker: "C2", title: "Semantic reconstruction", body: "Derived behavior labels with source labels.", color: C.green, fill: C.greenPale },
    { kicker: "C3", title: "Validation artifacts", body: "Genesys2/CVA6 runs, manifests, and checkers.", color: C.black, fill: C.pale },
  ]);
}

function scope(slide) {
  rowList(slide, [
    { label: "OBSERVED", text: "Linux user-mode workloads", color: C.blue },
    { label: "TRUSTED", text: "kernel, bitstream, runner, offline tools", color: C.black },
    { label: "EVIDENCE", text: "board trace plus labeled reference fields", color: C.green },
    { label: "EXCLUDED", text: "kernel/rootkit, bitstream tamper, malware eval", color: C.red },
  ], 250);
}

function appClaim(slide) {
  const cols = [
    { label: "HARDWARE TRACE", title: "Trace events", body: "syscalls, traps, returns, drops", color: C.blue, fill: C.bluePale },
    { label: "LOCAL CODE", title: "Attribution", body: "ELF hash, symbols, syscall sites", color: C.green, fill: C.greenPale },
    { label: "MALWARE ANALYSIS", title: "Behavior rules", body: "rule families, lineage, limitations", color: C.amber, fill: C.amberPale },
  ];
  cols.forEach((c, i) => {
    const x = 92 + i * 385;
    rect(slide, x, 272, 330, 210, c.fill, c.color, 2);
    text(slide, c.label, x + 26, 304, 250, 22, { size: 13, bold: true, color: c.color, mono: true });
    text(slide, c.title, x + 26, 348, 260, 36, { size: 28, bold: true, color: C.ink });
    text(slide, c.body, x + 26, 404, 260, 44, { size: 19, color: C.muted });
  });
  text(slide, "Core claim: trace-backed behavior analysis, not a mature classifier.", 120, 540, 1040, 30, { size: 23, bold: true, color: C.red, align: "center" });
}

function appPipeline(slide) {
  const y = 286;
  const steps = [
    ["trace", "board events", C.blue],
    ["code map", "local ELF view", C.green],
    ["join", "PC + process scope", C.black],
    ["graph", "semantic events", C.blue],
    ["rules", "behavior labels", C.amber],
  ];
  steps.forEach(([top, bottom, color], i) => {
    const x = 70 + i * 235;
    if (i > 0) rect(slide, x - 48, y + 62, 46, 4, C.blue);
    rect(slide, x, y, 190, 128, i === 4 ? C.amberPale : C.pale, color, 2);
    text(slide, top, x + 16, y + 32, 158, 28, { size: 22, bold: true, color: color, mono: true, align: "center" });
    text(slide, bottom, x + 16, y + 76, 158, 24, { size: 16, bold: true, color: C.body, align: "center" });
  });
  rowList(slide, [
    { label: "SEPARATE", text: "hardware trace is kept separate from reference labels", color: C.blue },
    { label: "TAG", text: "code and behavior claims carry source labels", color: C.green },
  ], 500, { step: 64, textSize: 22, textHeight: 32, lineOffset: 50 });
}

function implementationStatus(slide) {
  const rows = [
    { label: "35T", text: "13/13 matrix PASS; 6/6 behavior cases PASS", color: C.green },
    { label: "CVA6", text: "12 case studies PASS; 8 safe surrogates", color: C.blue },
    { label: "LIMIT", text: "no accuracy, payload-equivalence, or source-line claim", color: C.red },
  ];
  rowList(slide, rows, 265, { step: 96, textSize: 23, textHeight: 46, lineOffset: 70, textW: 840 });
}

function pipeline(slide) {
  const nodes = ["CVA6\ncommit", "trace\nadapter", "filter +\ndrop log", "BRAM\nring", "event\nrecon.", "check\nscripts"];
  nodes.forEach((n, i) => {
    const x = 74 + i * 196;
    const y = 325;
    if (i < nodes.length - 1) rect(slide, x + 158, y + 53, 38, 4, C.blue);
    rect(slide, x, y, 160, 106, i < 2 ? C.bluePale : C.pale, i === 0 ? C.blue : C.hair, 2);
    text(slide, n, x + 18, y + 28, 124, 52, { size: 23, bold: true, color: C.ink, align: "center" });
  });
}

function eventModel(slide) {
  rowList(slide, [
    { label: "CONTROL", text: "retire, branch, jump", color: C.blue },
    { label: "SYSCALL", text: "entry and qualified return", color: C.green },
    { label: "CONTEXT", text: "trap, CSR, SATP, privilege", color: C.black },
    { label: "ACCOUNT", text: "ARG_MEM, marker, drop records", color: C.amber },
  ], 250);
}

function syscall(slide) {
  const items = [
    ["1", "U-mode ECALL", "SYSCALL_ENTRY"],
    ["2", "kernel interval", "outstanding state"],
    ["3", "SRET to U-mode", "SYSCALL_RET"],
  ];
  items.forEach(([n, title, sub], i) => {
    const x = 120 + i * 365;
    rect(slide, x, 310, 285, 150, C.white, i === 2 ? C.blue : C.hair, 2);
    text(slide, n, x + 24, 350, 52, 48, { size: 42, bold: true, color: i === 2 ? C.blue : C.muted, mono: true });
    text(slide, title, x + 90, 338, 170, 34, { size: 24, bold: true, color: C.ink });
    text(slide, sub, x + 90, 395, 170, 24, { size: 16, bold: true, color: C.muted, mono: true });
    if (i < 2) rect(slide, x + 295, 382, 50, 4, C.blue);
  });
  text(slide, "Rejected: bad SRET or no outstanding syscall", 360, 528, 560, 30, { size: 22, bold: true, color: C.red, align: "center" });
}

function sourceBreakdown(slide) {
  const rows = [
    ["hardware fields", 12, C.green],
    ["reference fields", 276, C.amber],
    ["scoped string groups", 46, C.blue],
  ];
  rows.forEach(([label, value, color], i) => {
    const y = 280 + i * 90;
    text(slide, label, 170, y, 280, 30, { size: 24, bold: true, color: C.ink });
    rect(slide, 500, y + 5, 420, 24, C.pale, C.hair, 1);
    rect(slide, 500, y + 5, Math.max(20, 420 * value / 276), 24, color);
    text(slide, String(value), 960, y - 4, 110, 38, { size: 34, bold: true, color });
  });
  text(slide, "Do not present reference-derived semantics as hardware observations.", 260, 575, 760, 28, { size: 20, bold: true, color: C.red, align: "center" });
}

function localCode(slide) {
  threeBlocks(slide, [
    { kicker: "CODE MAP", title: "ELF identity", body: "hash, load ranges, sections, symbols", color: C.green, fill: C.greenPale },
    { kicker: "JOIN", title: "Trace to code", body: "PC evidence plus process/runtime scope", color: C.blue, fill: C.bluePale },
    { kicker: "LIMITATION", title: "No source-line claim", body: "DWARF/source-line attribution needs board evidence", color: C.red, fill: C.redPale },
  ], 270);
}

function app35t(slide) {
  const items = [
    ["13/13", "synthetic matrix", C.green],
    ["512", "trace records", C.blue],
    ["PASS", "fd/path + process tree", C.green],
    ["6/6", "malware-derived behavior cases", C.amber],
  ];
  items.forEach(([v, label, color], i) => {
    const x = 105 + i * 282;
    rect(slide, x, 278, 230, 150, i === 3 ? C.amberPale : color === C.green ? C.greenPale : C.bluePale, color, 2);
    text(slide, v, x + 26, 310, 170, 44, { size: v === "PASS" ? 38 : 44, bold: true, color, mono: true });
    text(slide, label, x + 26, 372, 165, 34, { size: 17, bold: true, color: C.ink });
  });
  rect(slide, 205, 510, 870, 44, C.redPale, C.red, 1);
  text(slide, "Implemented as a safety-controlled prototype; not malware-family accuracy.", 205, 521, 870, 22, { size: 20, bold: true, color: C.red, align: "center" });
}

function genesysStatus(slide) {
  rowList(slide, [
    { label: "PASS", text: "12 controlled case studies in current manifest", color: C.green },
    { label: "PASS", text: "8 safe malware-behavior surrogate case studies", color: C.green },
    { label: "LIMITED", text: "local code fixtures pass; source-line attribution not claimed", color: C.amber },
    { label: "NO CLAIM", text: "real malware validation and detector accuracy", color: C.red },
  ], 245, { step: 82, textSize: 23, textHeight: 42, lineOffset: 60, textW: 850 });
}

function artifacts(slide) {
  rowList(slide, [
    { label: "RTL", text: "trace_top, rvfi adapter, BRAM ring", color: C.blue },
    { label: "BOARD", text: "Genesys2/CVA6 current evidence root", color: C.black },
    { label: "ANALYSIS", text: "decoder, behavior audit, source-label summaries", color: C.green },
    { label: "CHECKERS", text: "tools/check_* and rvmt repro commands", color: C.amber },
  ], 250);
}

function evalMap(slide) {
  threeBlocks(slide, [
    { kicker: "SUPPORTED", title: "Core evidence", body: "correctness, source labels, board runs, resource/timing", color: C.green, fill: C.greenPale },
    { kicker: "LIMITED", title: "Scoped claims", body: "source lines, strings, benign controls, tracer baseline", color: C.amber, fill: C.amberPale },
    { kicker: "UNSUPPORTED", title: "Not claimed", body: "transport, overhead, real malware validation", color: C.red, fill: C.redPale },
  ]);
}

function heroMetric(slide) {
  text(slide, "122", 92, 242, 430, 124, { size: 112, bold: true, color: C.blue, mono: true });
  text(slide, "accepted board runs", 105, 386, 470, 42, { size: 31, bold: true, color: C.ink });
  rect(slide, 618, 248, 2, 280, C.hair);
  const facts = [["12", "samples"], ["126", "attempts"], ["4", "failed retained"], ["0", "drops / wraps / gaps"]];
  facts.forEach(([v, lab], i) => {
    const x = 690 + (i % 2) * 240;
    const y = 260 + Math.floor(i / 2) * 128;
    text(slide, v, x, y, 145, 52, { size: 46, bold: true, color: i === 3 ? C.green : C.ink, mono: true });
    text(slide, lab, x, y + 60, 170, 24, { size: 18, bold: true, color: C.muted });
  });
}

function workloads(slide) {
  const rows = [
    ["safe baseline", "4 samples", "42 accepted reps", C.blue],
    ["surrogate", "8 samples", "80 accepted reps", C.black],
    ["benign controls", "5 samples", "scoped controls", C.green],
  ];
  rows.forEach(([label, samples, note, color], i) => {
    const y = 280 + i * 92;
    text(slide, label, 180, y, 220, 30, { size: 24, bold: true, color: C.ink });
    rect(slide, 430, y + 8, 250, 24, C.pale, C.hair, 1);
    rect(slide, 430, y + 8, 50 + (i + 1) * 55, 24, color);
    text(slide, samples, 760, y, 190, 28, { size: 24, bold: true, color });
    text(slide, note, 760, y + 34, 220, 22, { size: 17, color: C.muted });
  });
}

function audit(slide) {
  const metrics = [["syscall recall", "1.0"], ["precision", "1.0"], ["argument recon.", "1.0"], ["benign FPR", "0.0"]];
  metrics.forEach(([label, value], i) => {
    const x = 110 + i * 270;
    rect(slide, x, 292, 220, 145, i === 3 ? C.greenPale : C.bluePale, i === 3 ? C.green : C.blue, 2);
    text(slide, value, x + 26, 318, 160, 48, { size: 42, bold: true, color: i === 3 ? C.green : C.blue, mono: true });
    text(slide, label, x + 26, 382, 165, 28, { size: 18, bold: true, color: C.ink });
  });
  rect(slide, 245, 502, 790, 44, C.redPale, C.red, 1);
  text(slide, "Controlled workload analysis only. Not detection accuracy.", 245, 513, 790, 22, { size: 20, bold: true, color: C.red, align: "center" });
}

function resources(slide) {
  const rows = [["LUT", 25.32, C.blue], ["FF", 16.18, C.green], ["BRAM18", 5.56, C.amber], ["DSP", 0, C.muted]];
  rows.forEach(([label, pct, color], i) => {
    const y = 270 + i * 72;
    text(slide, label, 205, y, 120, 30, { size: 24, bold: true, color: C.ink, mono: true });
    rect(slide, 370, y + 6, 450, 22, C.pale, C.hair, 1);
    rect(slide, 370, y + 6, 450 * pct / 30, 22, color);
    text(slide, `+${pct.toFixed(2)}%`, 860, y, 145, 30, { size: 22, bold: true, color });
  });
  text(slide, "Timing MET, slack 0.177 ns. Cycle-level runtime overhead remains unsupported.", 205, 562, 870, 28, { size: 20, bold: true, color: C.red, align: "center" });
}

function repro(slide) {
  rowList(slide, [
    { label: "MANIFEST", text: "current artifact root accepted", color: C.green },
    { label: "ARCHIVE", text: "3160 files, 316.9 MB, SHA d5b806...433b", color: C.blue },
    { label: "CHECKERS", text: "repro:quick and documented full gates pass", color: C.black },
    { label: "PAPER", text: "NDSS draft builds; figures and quantitative tables still need final polish", color: C.amber },
  ], 250);
}

function claimBoundary(slide) {
  rowList(slide, [
    { label: "WRITE", text: "hardware-assisted behavior tracing and analysis", color: C.green },
    { label: "WRITE", text: "35T end-to-end prototype; scoped CVA6 evidence", color: C.green },
    { label: "LIMIT", text: "synthetic and safety-controlled malware-derived behaviors", color: C.amber },
    { label: "DO NOT", text: "real-malware accuracy, payload equivalence, production detector", color: C.red },
  ], 242, { textSize: 23, textHeight: 44, lineOffset: 62, textW: 850 });
}

function paperStory(slide) {
  const steps = [
    ["Problem", "trace to behavior"],
    ["Conclusion", "controlled recon."],
    ["Evidence", "tests + board"],
    ["Decision", "claim + gap"],
  ];
  steps.forEach(([a, b], i) => {
    const x = 92 + i * 288;
    const color = i === 3 ? C.red : i === 2 ? C.green : C.blue;
    const fill = i === 3 ? C.redPale : i === 2 ? C.greenPale : C.bluePale;
    rect(slide, x, 310, 245, 138, fill, color, 2);
    text(slide, a, x + 22, 340, 190, 28, { size: 20, bold: true, color });
    text(slide, b, x + 22, 388, 185, 38, { size: 17, bold: true, color: C.ink });
  });
}

function ledger(slide) {
  rowList(slide, [
    { label: "PASS", text: "trace correctness; source labels; resources", color: C.green },
    { label: "LIMITED", text: "source lines; strings; benign controls; baseline", color: C.amber },
    { label: "NO CLAIM", text: "transport; overhead; real malware", color: C.red },
  ], 280, { textSize: 24, textHeight: 40, lineOffset: 62, step: 82 });
}

function correctness(slide) {
  threeBlocks(slide, [
    { kicker: "FIXTURE", title: "50 + 10", body: "directed and seeded random cases", color: C.blue, fill: C.bluePale },
    { kicker: "SENSITIVITY", title: "9", body: "negative sensitivity cases", color: C.green, fill: C.greenPale },
    { kicker: "SOURCES", title: "12 / 276", body: "hardware fields / reference fields", color: C.amber, fill: C.amberPale },
  ]);
}

function streaming(slide) {
  rowList(slide, [
    { label: "TARGET", text: "p99 = 0.0215755 event bytes/cycle", color: C.blue },
    { label: "REQUIRED", text: "0.0323633 event bytes/cycle, about 1.618 MB/s at 50 MHz", color: C.amber },
    { label: "CURRENT", text: "sustained streaming = 0; noninterference = false", color: C.red },
  ], 280);
}

function workloadRoster(slide) {
  rowList(slide, [
    { label: "SAFE", text: "hello_write; file_open_read_write; fork_exec; illegal_instruction", color: C.blue },
    { label: "SURROGATE", text: "file_scan; batch_open_read_write; self_copy_sim; abnormal_syscall_sequence", color: C.black },
    { label: "SURROGATE", text: "illegal_trap; process_chain; dynamic_executable_memory; anti_debug_like", color: C.black },
    { label: "BENIGN", text: "hello; cat; clock_status; getdents_only; mmap_rw", color: C.green },
  ], 232, { textSize: 20, textHeight: 58, lineOffset: 66, step: 82, textW: 830 });
}

function resourceTable(slide) {
  const cols = [330, 515, 700, 890];
  ["LUT", "FF", "BRAM18", "DSP"].forEach((h, i) => text(slide, h, cols[i], 255, 120, 24, { size: 18, bold: true, color: C.muted, mono: true }));
  const rows = [
    ["baseline", "84,923", "56,491", "108", "27"],
    ["trace", "106,428", "65,634", "114", "27"],
    ["delta", "+25.32%", "+16.18%", "+5.56%", "+0"],
  ];
  rows.forEach((r, i) => {
    const y = 312 + i * 78;
    text(slide, r[0], 165, y, 130, 28, { size: 22, bold: true, color: i === 2 ? C.blue : C.ink, mono: true });
    r.slice(1).forEach((v, j) => text(slide, v, cols[j], y, 130, 28, { size: 24, bold: true, color: i === 2 ? C.blue : C.ink }));
    rect(slide, 160, y + 46, 880, 1, C.hair);
  });
}

const renderers = {
  sixQuestionMap, whyMatters, currentConclusion, evidenceMapV6, sourceLabelsV6,
  alternativesV6, nextDecisionV6,
  problem, thesis, contrib, scope, appClaim, appPipeline, implementationStatus,
  pipeline, eventModel, syscall, sourceBreakdown, localCode, app35t, genesysStatus, artifacts,
  evalMap, heroMetric, workloads, audit, resources, repro, claimBoundary, paperStory,
  ledger, correctness, streaming, workloadRoster, resourceTable,
};

function renderSlide(presentation, s) {
  const slide = presentation.slides.add();
  if (s.kind === "cover") cover(slide, s);
  else {
    header(slide, s);
    renderers[s.kind]?.(slide, s);
  }
  notes(slide, s);
}

async function writeBlob(filePath, blob) {
  await fs.writeFile(filePath, Buffer.from(await blob.arrayBuffer()));
}

function mdTable(headers, rows) {
  const esc = (v) => String(v).replaceAll("|", "\\|").replaceAll("\n", "<br>");
  return [`| ${headers.join(" | ")} |`, `| ${headers.map(() => "---").join(" | ")} |`, ...rows.map((row) => `| ${row.map(esc).join(" | ")} |`)].join("\n");
}

async function writeDocs() {
  await fs.writeFile(path.join(OUT, "slide_visual_audit_v6.md"), [
    "# Slide Visual Audit for V6",
    "",
    "V6 reorganizes the weekly update around six research-meeting questions: problem, value, conclusion, evidence, boundaries, and next decisions.",
    "",
    "Core application status: the repository supports hardware-assisted behavior reconstruction for controlled RISC-V Linux workloads. It does not support real-malware accuracy, payload equivalence, production transport throughput, cycle-level overhead, or board-native source-line attribution claims.",
    "",
    mdTable(["Slide", "Professional slide issue found", "Final correction / role"], visualAudit),
    "",
  ].join("\n"), "utf8");

  await fs.writeFile(path.join(OUT, "terminology_audit_v6.md"), [
    "# RV-MalTrace Terminology Audit V6",
    "",
    "This file records terminology that was replaced, retained, or defined to avoid unsupported invented terms in the deck.",
    "",
    mdTable(["Old / candidate term", "Decision", "Deck wording", "Reason"], terminologyAudit),
    "",
  ].join("\n"), "utf8");

  await fs.writeFile(path.join(OUT, "outline_v6.md"), [
    "# RV-MalTrace Six-Question Weekly Outline V6",
    "",
    "The deck is organized so that a listener can answer six questions after the weekly meeting: research problem, motivation, current conclusion, supporting evidence, evidence boundaries, and next decisions.",
    "",
    ...slides.map((s) => [`## ${s.no}. ${s.title}${s.appendix ? " (Appendix)" : ""}`, "", `- Section: ${s.section}`, `- Claim: ${s.claim}`, `- Notes: ${s.notes}`, ""].join("\n")),
  ].join("\n"), "utf8");
}

function htmlEscape(v) {
  return String(v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

async function writeHtml() {
  const sections = slides.map((s) => `<section class="slide" data-layout="${s.kind === "cover" ? "SWISS-COVER-ASCII" : s.appendix ? "S15" : "S08"}">
  <div class="rail"></div>
  <div class="meta">${htmlEscape(s.section.toUpperCase())}<span>${htmlEscape(s.no)}</span></div>
  <h1>${htmlEscape(s.title)}</h1>
  <h2>${htmlEscape(s.claim)}</h2>
  <aside>${htmlEscape(s.notes)}</aside>
</section>`).join("\n");
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RV-MalTrace Paper Update</title><style>
:root{--ink:#111418;--blue:#0057FF;--muted:#68717D;--hair:#D8DEE6}*{box-sizing:border-box}body{margin:0;background:#111;color:var(--ink);font-family:"Microsoft YaHei UI","Noto Sans CJK SC",Arial,sans-serif}.deck{width:100vw;height:100vh;overflow:hidden}.slide{display:none;position:relative;width:100vw;height:56.25vw;max-height:100vh;max-width:177.7778vh;margin:auto;background:#fff;padding:5.2vw 7vw 4vw}.slide.active{display:block}.rail{position:absolute;left:0;top:0;width:1.1vw;height:100%;background:var(--blue)}.meta{position:absolute;left:5.6vw;right:5.6vw;top:2.8vw;font-size:1.05vw;font-weight:800;color:var(--blue);font-family:monospace}.meta span{float:right;color:var(--muted)}h1{margin:5.2vw 0 2vw;max-width:78vw;font-size:3vw;line-height:1.16}h2{max-width:75vw;font-size:1.65vw;line-height:1.4}aside{position:absolute;left:7vw;right:7vw;bottom:5vw;border-top:.18vw solid var(--hair);padding-top:1vw;color:var(--muted);font-size:1vw}.slide[data-layout="SWISS-COVER-ASCII"]{background:var(--blue);color:#fff}.slide[data-layout="SWISS-COVER-ASCII"] .rail{background:#fff}.slide[data-layout="SWISS-COVER-ASCII"] .meta,.slide[data-layout="SWISS-COVER-ASCII"] .meta span,.slide[data-layout="SWISS-COVER-ASCII"] aside{color:#fff}
</style></head><body><main class="deck">${sections}</main><script>const s=[...document.querySelectorAll('.slide')];let i=0;function show(n){i=(n+s.length)%s.length;s.forEach((x,j)=>x.classList.toggle('active',j===i))}addEventListener('keydown',e=>{if(['ArrowRight','PageDown',' '].includes(e.key))show(i+1);if(['ArrowLeft','PageUp'].includes(e.key))show(i-1)});show(0);</script></body></html>`;
  await fs.mkdir(WEB, { recursive: true });
  await fs.writeFile(path.join(WEB, "index.html"), html, "utf8");
}

async function build() {
  await fs.mkdir(OUT, { recursive: true });
  await fs.mkdir(PREVIEW, { recursive: true });
  await fs.mkdir(LAYOUT, { recursive: true });
  await writeDocs();
  await writeHtml();

  const presentation = Presentation.create({ slideSize: { width: W, height: H } });
  slides.forEach((s) => renderSlide(presentation, s));

  for (const [idx, slide] of presentation.slides.items.entries()) {
    const stem = `slide-${String(idx + 1).padStart(2, "0")}`;
    await writeBlob(path.join(PREVIEW, `${stem}.png`), await presentation.export({ slide, format: "png", scale: 1 }));
    await fs.writeFile(path.join(LAYOUT, `${stem}.layout.json`), await (await slide.export({ format: "layout" })).text(), "utf8");
  }
  const pptx = await PresentationFile.exportPptx(presentation);
  await pptx.save(path.join(OUT, "ndss_paper_update_v6.pptx"));
  const inspect = await presentation.inspect({ kind: "slide,textbox,shape,notes,layout", maxChars: 16000 });
  await fs.writeFile(path.join(OUT, "ndss_paper_update_v6.pptx.inspect.ndjson"), inspect.ndjson, "utf8");
}

build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
