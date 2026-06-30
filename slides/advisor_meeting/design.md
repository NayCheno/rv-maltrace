# Design Document

## 1. Profile Baseline Declaration

- **Profile selection**: `profiles/academic.md`
- **Selection rationale**: This is a PhD research progress presentation for a first meeting with the advisor. The audience is a senior professor (博导) in computer architecture/security. Academic rigor, logical clarity, and information density are paramount.
- **Referenced dimensions**: High information density (70-85% fill), chart-dominant text-to-visual ratio, argumentation-driven narrative style, clean/restrained/professional color guidance, sans-serif readability fonts, navigation bar for progress tracking, original figure reuse strategy, decoration prohibitions (no flashy backgrounds, no decorative icons, no gradients/shadows on charts).
- **Deviation notes**:
  - Since this is a *progress report* rather than a final thesis defense, we allow slightly more architectural diagrams and workflow visuals than a pure results-focused defense.
  - The user explicitly wants to cover 7 deep points, so we will use more text-heavy slides than typical results-only defenses, but still organize with diagrams and tables where possible.
  - No university logo is specified, so we omit it.

## 2. Style Baseline Declaration

- **Style anchor selection**:
  - **Nature/Science paper figure style**: Referenced for clean chart aesthetics, minimal color palettes, and high data readability.
  - **Swiss International Style**: Referenced for grid-based layout discipline, strong typographic hierarchy, and clear information architecture.
- **Referenced dimension explanation**:
  - From Nature/Science: chart styling (flat, annotated, no decorative effects), figure numbering, and data-forward presentation.
  - From Swiss Style: grid alignment, typographic contrast (large titles vs. dense body text), use of lines for separation rather than boxes, and strict left/right alignment.

## 3. Style Details

### Color Design Principles

- **Overall tendency**: Conservative & steady. This is an academic advisor meeting — credibility and professionalism are non-negotiable.
- **Temperature**: Cool-neutral, leaning toward mineral/tech. The topic is hardware architecture and security; a cool, precise tone matches the subject matter.
- **Primary color**: `#1E3A5F` (deep navy-slate). Academic, authoritative, and distinct from generic blue. Avoids cheap "tech blue" while remaining readable.
- **Background**: `#F7F8FA` (very light cool gray). Not pure white — reduces glare and provides subtle warmth. Content pages use this; cover/chapter pages may use primary color.
- **Text color**: `#1A1D23` (near-black with slight blue undertone). High contrast against light gray.
- **Secondary color**: `#5B6B82` (slate gray). For subtitles, annotations, secondary text, divider lines.
- **Accent color**: `#B45309` (deep amber/burnt orange). Used extremely sparingly — only for key findings, core conclusions, KPI numbers, or critical warnings. It provides a warm counterpoint to the cool primary without being flashy.
- **Surface color**: `#FFFFFF` (white). For cards/containers if needed, but we prefer open layout with whitespace.

### Font Usage Principles

- **Title font**: `QuattrocentoSans, MiSans` — clean, academic, highly readable at large sizes. Bold weight for titles.
- **Body font**: `QuattrocentoSans, MiSans` — consistent with title font for cohesion. Regular weight for body.
- **Code/formula font**: `QuattrocentoSans, MiSans` (no special monospace needed for this presentation; RTL names are short enough).
- **Font size hierarchy**:
  - Cover title: 40px
  - Page title: 28px
  - Subtitle/section heading: 22px
  - Body text: 18px (heavy content pages) to 20px (moderate content)
  - Annotations/footnotes: 14px
  - Navigation bar: 14px
- **Special treatments**: Cover title uses bold + slightly expanded letter spacing (2px) for authority. Chapter numbers use very large font (72px) in low opacity as background decoration.

### Text Box and Container Styles

- **Content separation**: Primarily whitespace + font size hierarchy. Avoid card overuse.
- **When cards are used**: Sharp corners, no border, very subtle fill (`#FFFFFF` or `#EFF1F5`) to create minimal separation against the `#F7F8FA` background.
- **Decorative elements**:
  - Thin horizontal lines (`#1E3A5F` or `#5B6B82`, 1-2px) as section dividers.
  - Small accent rectangles (4px wide, `#B45309`) as left-edge markers for key points or quotes.
  - No textures, no gradients, no shadows on content elements.

### Image Style

- **Icons**: Solid style (`fas:`), used very sparingly and only when directly relevant to content (e.g., a CPU icon for architecture slides). Color matches primary or secondary.
- **Tables**: Minimal three-line style. Header row with primary color fill and white text. Body rows alternate white and very light gray. No vertical borders. Clean, academic.
- **Charts**: Flat, minimal. Primary + secondary + accent colors only. No 3D, no shadows, no gradient fills. Complete axis labels and legends.
- **Illustrations/Architecture diagrams**: Built using shapes (rectangles, arrows, lines) + text. Clean, flat, grid-aligned. No decorative illustrations.

## 4. Layout System

### Global Layout Characteristics

- **Page size**: 1280 x 720 (16:9)
- **Page margins**: Left/Right 60px, Top 80px (below nav bar), Bottom 50px
- **Navigation bar**: Horizontal top bar, height 50px, full width, primary color `#1E3A5F` fill. Contains 4 chapter titles evenly spaced. Current chapter highlighted with white text + subtle bottom border. Non-current chapters in 70% opacity white text.
- **Page title area**: Below nav bar, left-aligned, 28px bold, primary color. Often accompanied by a thin 2px accent line underneath spanning ~120px.
- **Page number**: Bottom-right, 14px, secondary color.
- **Grid alignment**: All elements strictly aligned to an invisible grid. Left-right layouts have equal visual weight. No floating unaligned elements.

### Special Page Layouts

- **Cover**: Hero design. Full-height primary color background (`#1E3A5F`). Centered large white title (40px). Subtitle below in lighter opacity. A thin horizontal accent line (`#B45309`, 3px, 80px wide) between title and subtitle. No nav bar on cover.
- **Table of Contents**: Left side large "CONTENTS" vertical text (or large horizontal) in primary color, low opacity. Right side: 4 chapter entries as a clean grid or list with chapter numbers in accent color and titles in text color. Dotted leaders or thin lines connecting numbers to titles.
- **Chapter dividers**: Full primary color background. Large chapter number (72px, white, 10% opacity) as background watermark. Chapter title in white, 36px, centered. A thin accent line below the title. No nav bar or minimal nav bar.
- **Final page**: Similar to cover but with discussion points. Primary color background. Key questions in white text. Contact/thank you below.

### Content Page Layout Patterns

- **Pattern A — Left-Right Split**: Left side 55% text (bullet points with accent markers), Right side 45% diagram/table. Used for architecture and pipeline slides.
- **Pattern B — Top-Bottom**: Top 30% title + summary sentence, Bottom 70% full-width diagram or table. Used for evaluation and evidence slides.
- **Pattern C — Full-width SmartArt**: Title at top, then a full-page architecture diagram built from shapes and arrows. Used for hardware trace architecture.
- **Pattern D — Two-column text**: Title at top, then two equal columns of text for comparison (e.g., challenges vs. strategies). Used for challenge/response slides.
- **Pattern E — Table + Conclusion**: Full-width table occupying 70% of page, bottom 30% a highlighted conclusion box with accent left-border. Used for evaluation metrics.

## 5. Style Usage Rules

- **$title** textStyle: Cover title, chapter titles.
- **$subtitle** textStyle: Page subtitles, cover subtitle.
- **$heading** textStyle: Page titles on content pages.
- **$body** textStyle: Main body text, bullet points.
- **$caption** textStyle: Footnotes, annotations, page numbers, source citations.
- **$nav** textStyle: Navigation bar text.
- **$primary** color: Page titles, nav bar background, chapter backgrounds, key headings.
- **$secondary** color: Subtitles, annotations, divider lines, secondary text.
- **$accent** color: Key findings, critical numbers, accent markers, conclusion highlights. Use < 10% of page area.
- **$background** color: Content page backgrounds.
- **$text** color: Body text.
- **$surface** color: Card/container backgrounds if used.
- **Table style**: Header with `$primary` fill and white text; body alternating white and `#EFF1F5`; no vertical borders; thin horizontal borders in `#E2E5EA`.

## 6. Risk Prohibitions

- [ ] **No blue/cyan default tech colors**: The primary color `#1E3A5F` is a deep slate-navy, not a bright tech blue. Do not use `#0A97C0`, `#2C80FD`, or similar.
- [ ] **No gradient backgrounds or shadow effects**: Academic profile strictly prohibits these. Use flat fills only.
- [ ] **No decorative icons/illustrations**: Only functional icons directly related to technical content. No clip art, no stock photos on content pages.
- [ ] **No text-only walls**: Even on text-heavy slides, use accent left-borders, bullet hierarchy, and spacing to create visual structure. Never dump plain paragraphs.
- [ ] **No font size below 14px**: Minimum for captions/footnotes. Body text minimum 18px. Table text minimum 14px.
- [ ] **No misaligned left-right layouts**: If using two columns, ensure bottom edges are roughly aligned or intentionally balanced. No left-full-right-empty layouts.
- [ ] **No chart without annotations**: Any table/chart must have complete context — what the data means, what the claim boundary is.
- [ ] **No excessive card use**: Whitespace and typography should create hierarchy. Cards only when content groups genuinely need visual separation.
- [ ] **No flashy chapter pages**: Chapter pages should be clean — large number, title, accent line. No 3D effects, no complex shapes.
- [ ] **No hallucinated data**: All numbers, metrics, and evidence claims must come from the actual repository docs (e.g., 122 accepted windows, 0 drops, etc.).

## 7. Theme Definition

```yaml
theme:
  colors:
    primary: "#1E3A5F"
    secondary: "#5B6B82"
    accent: "#B45309"
    background: "#F7F8FA"
    text: "#1A1D23"
    surface: "#FFFFFF"
    lightbg: "#EFF1F5"
  textStyles:
    title:
      fontSize: 40
      color: "#FFFFFF"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.2
      letterSpacing: 2
    subtitle:
      fontSize: 22
      color: "#FFFFFF"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.4
    heading:
      fontSize: 28
      color: "$primary"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.3
    body:
      fontSize: 18
      color: "$text"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.6
    caption:
      fontSize: 14
      color: "$secondary"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.4
    nav:
      fontSize: 14
      color: "#FFFFFF"
      fontFamily: "QuattrocentoSans, MiSans"
      lineHeight: 1.2
  tableStyles:
    default:
      fontSize: 16
      fontFamily: "QuattrocentoSans, MiSans"
      headerFill: "$primary"
      headerColor: "#FFFFFF"
      headerBold: true
      bodyFill: ["#FFFFFF", "#EFF1F5"]
      bodyColor: "$text"
      border:
        style: solid
        width: 1
        color: "#E2E5EA"
```
