import fs from "node:fs/promises";
import path from "node:path";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const OUT = path.resolve(process.argv[2] || "slides");
const PREVIEW = path.join(OUT, "preview-v5");
const LAYOUT = path.join(OUT, "layout-v5");
const WEB = path.join(OUT, "web-v5");
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
    section: "Paper Framing",
    title: "RV-MalTrace",
    claim: "Hardware-assisted behavior tracing for RISC-V Linux workloads",
    kind: "cover",
    notes: "论文中心叙事：这不是 advisor decision deck，也不是 malware detector。核心论文对象是 hardware-assisted tracing、code attribution 和 provenance-aware semantic reconstruction。provenance 在这里按常规定义使用：每个高层语义标签必须能追溯到 trace、code map 或 oracle/reference field。",
  },
  {
    no: "02",
    section: "Research Problem",
    title: "Software-only tracing changes the observation surface",
    claim: "Software tracers are useful references, but visible to workloads.",
    kind: "problem",
    notes: "问题写成 paper problem：strace/QEMU/host logs 是必要 reference/oracle，但对抗性 workload 可感知软件观测面。oracle 是测试领域常用术语；主 slide 使用 reference，避免听众误读。",
  },
  {
    no: "03",
    section: "Thesis",
    title: "Trace events first; derived semantics carry provenance",
    claim: "The paper claims a trace-backed behavior analysis pipeline.",
    kind: "thesis",
    notes: "论文主张不是泛泛的 trace substrate，而是 hardware trace + code map + rule-based behavior analysis。provenance 是标准数据谱系/证据追踪术语，不是自造词；真实 malware 检测准确率仍不是当前 claim。",
  },
  {
    no: "04",
    section: "Contributions",
    title: "Three contributions define the paper",
    claim: "Each contribution maps to code and evidence in the repository.",
    kind: "contrib",
    notes: "贡献页只讲三点：CVA6 out-of-band trace collection、semantic reconstruction with provenance、Genesys2/CVA6 validation artifacts。",
  },
  {
    no: "05",
    section: "Core Application",
    title: "The application is trace-backed behavior analysis",
    claim: "Hardware trace, local code analysis, and malware-behavior rules are joined.",
    kind: "appClaim",
    notes: "回应核心问题：应用不是单独的 trace，也不是单独的 malware detector，而是把硬件 trace、本地 ELF/code-map 分析、malware-behavior taxonomy/rules 连接起来。trace-backed behavior analysis 是描述性组合词，页内拆成三列解释。",
  },
  {
    no: "06",
    section: "How It Works",
    title: "Implementation joins three data sources",
    claim: "Trace events stay separate from code attribution and behavior labels.",
    kind: "appPipeline",
    notes: "实现路径：trace.jsonl -> semantic_events/behavior_graph；ELF/code_map -> trace-code join；manifest/rules -> rule-based malware-behavior analysis。用 data sources 替代 evidence planes，避免生造术语。",
  },
  {
    no: "07",
    section: "Implementation Status",
    title: "Implemented as a scoped prototype",
    claim: "35T is end-to-end; Genesys2/CVA6 supports scoped evidence.",
    kind: "implementationStatus",
    notes: "35T: 13/13 synthetic matrix + 6/6 malware-derived safety-controlled behavior cases。Genesys2/CVA6: 12 controlled case studies, 8 safe surrogate case studies, local code fixtures PASS, but not real-malware validation。scoped prototype 是标准项目/论文表述，比 bounded app 更自然。",
  },
  {
    no: "08",
    section: "System Overview",
    title: "CVA6 commit events feed semantic reconstruction",
    claim: "The CVA6 path is sideband trace plus offline reconstruction.",
    kind: "pipeline",
    notes: "保留 CVA6 的论文贡献：从 commit-time trace 到 semantic event reconstruction，再到 validation scripts/checkers。此处不把它写成完整 malware detector。",
  },
  {
    no: "09",
    section: "Trace Semantics",
    title: "Trace records capture transitions and drops",
    claim: "The trace format is the contract between RTL and analysis.",
    kind: "eventModel",
    notes: "事件类型来自 trace_format.md：retire/control-flow/syscall/trap/context/memory/drop。这里按类别表达，不把所有枚举塞满。",
  },
  {
    no: "10",
    section: "Local Code Analysis",
    title: "Code maps make trace evidence attributable",
    claim: "ELF identity, symbols, syscall sites, and runtime maps constrain attribution.",
    kind: "localCode",
    notes: "本地代码分析包括 build_code_map、join_trace_code_map、source attribution summary。Genesys2 local fixtures PASS，但 board-native DWARF/source-line 仍不能声称。",
  },
  {
    no: "11",
    section: "35T Closure",
    title: "The 35T end-to-end path is implemented",
    claim: "35T connects trace capture, code-map join, and behavior rules.",
    kind: "app35t",
    notes: "35T evidence: 13/13 synthetic matrix PASS, 512-record trace budget, fd/path and process-tree targeted validation PASS, 6/6 malware-derived safety-controlled behavior cases PASS。",
  },
  {
    no: "12",
    section: "Genesys2/CVA6 Status",
    title: "CVA6 supports the current paper evidence",
    claim: "It is not yet a real-malware validation or source-line attribution claim.",
    kind: "genesysStatus",
    notes: "Genesys2/CVA6 current: case_study_manifest PASS with 12 case studies; 8 safe surrogate case studies; rule-based behavior analysis metrics PASS; local code fixtures PASS_LOCAL_CODE_ANALYSIS_FIXTURES; real malware containment PASS but no payloads in repo。",
  },
  {
    no: "13",
    section: "Evaluation Design",
    title: "Separate supported, limited, and unsupported claims",
    claim: "The paper must separate implementation evidence from nonclaims.",
    kind: "evalMap",
    notes: "RQ 不要写成 submission traffic light，而是写成 evaluation design：supported evidence、limited evidence、unsupported claims。",
  },
  {
    no: "14",
    section: "Genesys2/CVA6 Result",
    title: "122 accepted board runs",
    claim: "This is the strongest current CVA6 empirical result.",
    kind: "heroMetric",
    notes: "12 samples, 126 attempts, 122 accepted reps, 4 failed retained, 0 drops/wraps/gaps in accepted windows。",
  },
  {
    no: "15",
    section: "Workloads",
    title: "Controlled workloads, not in-the-wild malware",
    claim: "The workload set supports tracing validation under controlled behavior coverage.",
    kind: "workloads",
    notes: "4 safe baseline programs, 8 malware-behavior surrogate workloads, 5 benign controls。不要称真实 malware benchmark。surrogate 是安全实验中常用术语，这里指 repo-authored、safety-controlled implementations。",
  },
  {
    no: "16",
    section: "Behavior Audit",
    title: "Rule-based behavior analysis passes scoped checks",
    claim: "These metrics validate reconstruction, not detector accuracy.",
    kind: "audit",
    notes: "指标全过容易被误读，所以图内必须写 controlled-only / not detection accuracy。",
  },
  {
    no: "17",
    section: "Cost",
    title: "Resource cost is measured; overhead is not",
    claim: "Timing/resource evidence supports implementation cost, not cycle slowdown.",
    kind: "resources",
    notes: "LUT +25.32%, FF +16.18%, BRAM18 +5.56%, DSP +0, timing MET slack 0.177 ns。不能写 runtime slowdown。",
  },
  {
    no: "18",
    section: "Reproducibility",
    title: "The artifact package is reviewable",
    claim: "Evidence packaging and checkers are ahead of manuscript completeness.",
    kind: "repro",
    notes: "raw archive 3160 files / 316.9 MB；repro quick/full pass；paper skeleton builds but content incomplete。",
  },
  {
    no: "19",
    section: "Claim Boundaries",
    title: "Claim boundaries are explicit",
    claim: "Unsupported topics become limitations or future work.",
    kind: "claimBoundary",
    notes: "以论文写作边界为中心：可以写 trace-backed behavior analysis 和 35T end-to-end prototype，不能写 mature malware detector 或 CVA6 real-malware accuracy。",
  },
  {
    no: "20",
    section: "Paper Story",
    title: "Paper narrative",
    claim: "Hardware trace + code attribution + rule-based malware-behavior analysis.",
    kind: "paperStory",
    notes: "收尾不再让导师拍板，而是给出论文中心叙事：problem -> trace-backed analysis pipeline -> scoped prototype -> limitations/future work。",
  },
  {
    no: "21",
    section: "Appendix",
    title: "Streaming/DMA remains future work",
    claim: "Readiness and target profiles are not throughput evidence.",
    kind: "streaming",
    appendix: true,
    notes: "target p99 0.0215755 B/cycle; required 0.0323633 B/cycle; at 50 MHz required 1.618 MB/s; current sustained=0, noninterference=false。",
  },
  {
    no: "22",
    section: "Appendix",
    title: "Workload roster",
    claim: "Sample names are appendix material, not main-story material.",
    kind: "workloadRoster",
    appendix: true,
    notes: "列出 safe baseline、malware-behavior surrogates、benign controls。P0 safe 是内部分组名，正文不使用。",
  },
  {
    no: "23",
    section: "Appendix",
    title: "Resource detail",
    claim: "Resource/timing claim is supported; runtime overhead is not.",
    kind: "resourceTable",
    appendix: true,
    notes: "baseline vs trace-enabled resource table。",
  },
];

const visualAudit = [
  ["01", "Cover previously framed the meeting rather than the paper.", "Paper title, one scope statement, and a standard signal: TRACE EVENTS FIRST."],
  ["02", "Problem statement was too card-heavy for a research deck.", "Two spacious contrast boxes explain why software observers are insufficient."],
  ["03", "The thesis needed to separate hardware observations from semantic labels.", "Use trace events and provenance, with provenance defined as source tags."],
  ["04", "Contribution text risked becoming a shopping list.", "Three equal cards map directly to trace collection, semantic reconstruction, and validation artifacts."],
  ["05", "Core application was not explicit enough.", "Make the application the slide: trace-backed behavior analysis."],
  ["06", "Pipeline labels were previously too long and likely to wrap badly.", "Use standard pipeline language: data sources, code map, semantic events, behavior rules."],
  ["07", "Status page text was still too verbose after the first v4 pass.", "Shorten to three rows: 35T end-to-end, CVA6 scoped, limits explicit."],
  ["08", "System overview could be mistaken for a complete detector architecture.", "Keep only the CVA6 trace-to-validation path and one scoped claim."],
  ["09", "Trace semantics needed a contract view rather than raw detail.", "Four compact rows cover control, syscall, context, and accounting records."],
  ["10", "Local code analysis was under-explained.", "Three cards cover ELF identity, trace-to-code join, and the missing source-line claim."],
  ["11", "35T evidence had to be connected to the implemented path.", "Use four numeric cards and a red caveat to show end-to-end support without overclaiming."],
  ["12", "CVA6 evidence needed implementation status, not vague progress.", "Four rows separate board evidence, surrogate coverage, fixtures, and nonclaims."],
  ["13", "Evaluation slide risked mixing proof, scope, and blockers.", "Use supported / limited / unsupported claim categories."],
  ["14", "Main empirical result could be buried among small metrics.", "Use 122 as the hero number and push supporting counts to the right."],
  ["15", "Workload discussion could imply in-the-wild malware benchmarking.", "Three horizontal groups state safe baseline, surrogate workloads, and benign controls."],
  ["16", "Perfect metrics could be misread as detector accuracy.", "Large metric blocks plus a red footer: controlled workload analysis only."],
  ["17", "Resource result needed a cost claim, not runtime-overhead wording.", "Bar chart keeps resource deltas visible and states overhead is unsupported."],
  ["18", "Reproducibility page was too close to project-management status.", "Artifact package rows show manifest, archive, checkers, and paper maturity."],
  ["19", "Claim boundary needed to be paper-centered.", "Ledger says what to write, what to limit, and what not to claim."],
  ["20", "Story slide had to center the paper rather than advisors.", "Four cards connect problem, mechanism, application, and boundary."],
  ["21", "Streaming/DMA details were dense and easy to misread.", "Three clean rows state target, required throughput, and current future-work item."],
  ["22", "Sample names are long and can easily overflow.", "Widen the text lane and keep the roster in appendix only."],
  ["23", "Resource table labels previously wrapped awkwardly.", "Short row labels and wider numeric columns keep the appendix table stable."],
];

const terminologyAudit = [
  ["hardware-rooted", "Replaced", "hardware-assisted", "Hardware-assisted tracing is a standard systems term; hardware-rooted sounded like a slogan."],
  ["trace facts", "Replaced", "trace events / hardware observations", "Trace event is the standard term for records emitted by a tracing system."],
  ["evidence-chain audit", "Replaced", "trace-backed behavior analysis", "The new phrase describes the actual pipeline without inventing a named method."],
  ["lower surface", "Replaced", "out-of-band trace / hardware path", "Out-of-band and sideband are standard trace/monitoring terms."],
  ["evidence planes", "Replaced", "data sources", "Data source is clear and standard; no new abstraction is needed."],
  ["derived rows", "Replaced", "malware-derived behavior cases", "Behavior case is clearer and maps to the repository's case-study evidence."],
  ["No free source lines", "Replaced", "No source-line attribution claim", "Source-line attribution is the standard term."],
  ["P0 safe", "Replaced in main slides", "safe baseline", "P0 safe is kept only as an internal grouping name in notes."],
  ["oracle", "Explained", "reference/oracle", "Oracle is a standard testing term; main slides use reference for readability."],
  ["provenance", "Kept and defined", "source tags for derived labels", "Provenance is standard in data lineage and auditability."],
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
    { kicker: "C2", title: "Semantic reconstruction", body: "Derived behavior labels with provenance.", color: C.green, fill: C.greenPale },
    { kicker: "C3", title: "Validation artifacts", body: "Genesys2/CVA6 runs, manifests, and checkers.", color: C.black, fill: C.pale },
  ]);
}

function scope(slide) {
  rowList(slide, [
    { label: "OBSERVED", text: "Linux user-mode workloads", color: C.blue },
    { label: "TRUSTED", text: "kernel, bitstream, runner, offline tools", color: C.black },
    { label: "EVIDENCE", text: "board trace plus tagged oracle fields", color: C.green },
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
    { label: "TAG", text: "code and behavior claims carry provenance", color: C.green },
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

function provenance(slide) {
  const rows = [
    ["hardware fields", 12, C.green],
    ["oracle fields", 276, C.amber],
    ["scoped string groups", 46, C.blue],
  ];
  rows.forEach(([label, value, color], i) => {
    const y = 280 + i * 90;
    text(slide, label, 170, y, 280, 30, { size: 24, bold: true, color: C.ink });
    rect(slide, 500, y + 5, 420, 24, C.pale, C.hair, 1);
    rect(slide, 500, y + 5, Math.max(20, 420 * value / 276), 24, color);
    text(slide, String(value), 960, y - 4, 110, 38, { size: 34, bold: true, color });
  });
  text(slide, "Do not present oracle-derived semantics as hardware observations.", 260, 575, 760, 28, { size: 20, bold: true, color: C.red, align: "center" });
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
    { label: "ANALYSIS", text: "decoder, behavior audit, provenance summaries", color: C.green },
    { label: "CHECKERS", text: "tools/check_* and rvmt repro commands", color: C.amber },
  ], 250);
}

function evalMap(slide) {
  threeBlocks(slide, [
    { kicker: "SUPPORTED", title: "Core evidence", body: "correctness, provenance, board runs, resource/timing", color: C.green, fill: C.greenPale },
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
    { label: "PAPER", text: "LaTeX skeleton builds, content incomplete", color: C.amber },
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
    ["Problem", "visible software observers"],
    ["Mechanism", "commit events + code map"],
    ["Application", "rule-based analysis"],
    ["Boundary", "no mature detector claim"],
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
    { label: "PASS", text: "trace correctness; provenance; resources", color: C.green },
    { label: "LIMITED", text: "source lines; strings; benign controls; baseline", color: C.amber },
    { label: "NO CLAIM", text: "transport; overhead; real malware", color: C.red },
  ], 280, { textSize: 24, textHeight: 40, lineOffset: 62, step: 82 });
}

function correctness(slide) {
  threeBlocks(slide, [
    { kicker: "FIXTURE", title: "50 + 10", body: "directed and seeded random cases", color: C.blue, fill: C.bluePale },
    { kicker: "SENSITIVITY", title: "9", body: "negative sensitivity cases", color: C.green, fill: C.greenPale },
    { kicker: "PROVENANCE", title: "12 / 276", body: "hardware fields / oracle fields", color: C.amber, fill: C.amberPale },
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
  problem, thesis, contrib, scope, appClaim, appPipeline, implementationStatus,
  pipeline, eventModel, syscall, provenance, localCode, app35t, genesysStatus, artifacts,
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
  await fs.writeFile(path.join(OUT, "slide_visual_audit_v5.md"), [
    "# Slide Visual Audit for V5",
    "",
    "V5 keeps the paper-centered story and removes or defines nonstandard terminology.",
    "",
    "Core application status: the repository supports trace-backed behavior analysis, not a mature malware detector. The 35T path supports an end-to-end prototype for hardware trace + local code attribution + rule-based malware-behavior analysis under controlled limits. The Genesys2/CVA6 path supports scoped paper evidence through board runs, safe surrogate case studies, local code fixtures, and containment records, but it does not support real-malware accuracy, payload equivalence, or board-native source-line attribution.",
    "",
    mdTable(["Slide", "Professional slide issue found", "Final correction / role"], visualAudit),
    "",
  ].join("\n"), "utf8");

  await fs.writeFile(path.join(OUT, "terminology_audit_v5.md"), [
    "# RV-MalTrace Terminology Audit V5",
    "",
    "This file records terminology that was replaced, retained, or defined to avoid unsupported invented terms in the deck.",
    "",
    mdTable(["Old / candidate term", "Decision", "Deck wording", "Reason"], terminologyAudit),
    "",
  ].join("\n"), "utf8");

  await fs.writeFile(path.join(OUT, "outline_v5.md"), [
    "# RV-MalTrace Paper-Centered Outline V5",
    "",
    "The deck is organized around the paper's trace-backed behavior analysis pipeline: hardware trace plus local code analysis plus rule-based malware-behavior analysis.",
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
  await pptx.save(path.join(OUT, "ndss_paper_update_v5.pptx"));
  const inspect = await presentation.inspect({ kind: "slide,textbox,shape,notes,layout", maxChars: 16000 });
  await fs.writeFile(path.join(OUT, "ndss_paper_update_v5.pptx.inspect.ndjson"), inspect.ndjson, "utf8");
}

build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
