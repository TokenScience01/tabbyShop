# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** Tabby Game and Market
**Generated:** 2026-10-19 08:48:38
**Category:** Desktop game operations dashboard

---

## Global Rules

### Color Palette

| Role | Hex | CSS Variable |
|------|-----|--------------|
| Primary | `#292E2D` | `--color-primary` |
| Secondary | `#343A37` | `--color-secondary` |
| CTA/Accent | `#3C7951` | `--color-cta` |
| Background | `#17191A` | `--color-background` |
| Text | `#E8ECEB` | `--color-text` |
| Muted text | `#AAB4B1` | `--color-muted` |
| Antique gold | `#9D875C` | `--color-gold` |
| Panel | `#222627` | `--color-panel` |

**Color Notes:** Neutral charcoal foundation with restrained in-game forest green and antique-gold controls. Keep rarity and network-health colors semantic; avoid warm casts across large surfaces.

### Typography

- **Heading Font:** System UI Semibold
- **Body Font:** System UI (PingFang SC on macOS; Microsoft YaHei on Windows)
- **Mood:** dashboard, data, analytics, code, technical, precise
- **Google Fonts:** [Fira Code + Fira Sans](https://fonts.google.com/share?selection.family=Fira+Code:wght@400;500;600;700|Fira+Sans:wght@300;400;500;600;700)

**CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap');
```

### Spacing Variables

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` / `0.25rem` | Tight gaps |
| `--space-sm` | `8px` / `0.5rem` | Icon gaps, inline spacing |
| `--space-md` | `12px` / `0.75rem` | Card and control spacing |
| `--space-lg` | `16px` / `1rem` | Standard card padding |
| `--space-xl` | `24px` / `1.5rem` | Section separation |
| `--space-2xl` | `48px` / `3rem` | Section margins |
| `--space-3xl` | `64px` / `4rem` | Hero padding |

### Shadow Depths

| Level | Value | Usage |
|-------|-------|-------|
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.05)` | Subtle lift |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.1)` | Cards, buttons |
| `--shadow-lg` | `0 10px 15px rgba(0,0,0,0.1)` | Modals, dropdowns |
| `--shadow-xl` | `0 20px 25px rgba(0,0,0,0.15)` | Hero images, featured cards |

---

## Component Specs

### Buttons

```css
/* Primary Button */
.btn-primary {
  background: #3C7951;
  color: #F4F7F4;
  padding: 10px 18px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}

.btn-primary:hover {
  background: #498D5D;
  transform: translateY(-1px);
}

/* Secondary Button */
.btn-secondary {
  background: #292E2D;
  color: #E1E6E3;
  border: 1px solid #535A56;
  padding: 10px 18px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}
```

### Cards

```css
.card {
  background: #222627;
  border-radius: 12px;
  padding: 24px;
  box-shadow: var(--shadow-md);
  transition: all 200ms ease;
  cursor: pointer;
}

.card:hover {
  box-shadow: var(--shadow-lg);
  transform: translateY(-2px);
}
```

### Inputs

```css
.input {
  padding: 10px 12px;
  color: #E8ECEB;
  background: #191D1E;
  border: 1px solid #535A56;
  border-radius: 8px;
  font-size: 16px;
  transition: border-color 200ms ease;
}

.input:focus {
  border-color: #75C69D;
  outline: none;
  box-shadow: 0 0 0 3px #75C69D20;
}
```

### Modals

```css
.modal-overlay {
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
}

.modal {
  background: white;
  border-radius: 16px;
  padding: 32px;
  box-shadow: var(--shadow-xl);
  max-width: 500px;
  width: 90%;
}
```

---

## Style Guidelines

**Style:** Slate dark dashboard with restrained mint accents

**Keywords:** Dark theme, low light, high contrast, deep black, midnight blue, eye-friendly, OLED, night mode, power efficient

**Best For:** Night-mode apps, coding platforms, entertainment, eye-strain prevention, OLED devices, low-light

**Key Effects:** Minimal glow (text-shadow: 0 0 10px), dark-to-light transitions, low white emission, high readability, visible focus

### Page Pattern

**Pattern Name:** Desktop operations dashboard

- Keep one application shell and one compact navigation row.
- Use a three-zone game workspace: persistent controls, character and current task, live map.
- Group secondary data into labeled subtabs; show one dense table at a time.
- Replace empty tables with a compact, illustrated empty state.

---

## Anti-Patterns (Do NOT Use)

- ❌ Duplicate title bars
- ❌ Empty tables stretched to fill the viewport
- ❌ Raw internal item codes in user-facing labels
- ❌ Multiple unrelated tables competing in one view

### Additional Forbidden Patterns

- ❌ **Emojis as icons** — Use SVG icons (Heroicons, Lucide, Simple Icons)
- ❌ **Missing cursor:pointer** — All clickable elements must have cursor:pointer
- ❌ **Layout-shifting hovers** — Avoid scale transforms that shift layout
- ❌ **Low contrast text** — Maintain 4.5:1 minimum contrast ratio
- ❌ **Instant state changes** — Always use transitions (150-300ms)
- ❌ **Invisible focus states** — Focus states must be visible for a11y

---

## Pre-Delivery Checklist

Before delivering any UI code, verify:

- [ ] No emojis used as icons (use SVG instead)
- [ ] All icons from consistent icon set (Heroicons/Lucide)
- [ ] `cursor-pointer` on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard navigation
- [ ] `prefers-reduced-motion` respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px
- [ ] No content hidden behind fixed navbars
- [ ] No horizontal scroll on mobile
