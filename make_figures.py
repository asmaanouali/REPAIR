#!/usr/bin/env python3
"""Generate all figures for the IR-SAM remediation chapter.

All output is written to ``rapport-pfe/figures`` as vector PDF (diagrams,
plots) so that LaTeX ``\\includegraphics`` embeds crisp, scalable graphics.
Diagrams are drawn with matplotlib primitives (no Graphviz dependency).

Run:  python make_figures.py
"""
from __future__ import annotations

import os
import math

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Patch
from matplotlib.lines import Line2D
import numpy as np

# --------------------------------------------------------------------------
# House style
# --------------------------------------------------------------------------
IRBLUE = "#1F4E79"
IRGREEN = "#2E7D32"
IRGRAY = "#555555"
IRLIGHT = "#EEF3F8"
IRRED = "#B23A3A"
IRAMBER = "#C9881F"

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 10,
        "axes.edgecolor": IRGRAY,
        "axes.labelcolor": "#222222",
        "text.color": "#222222",
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.04,
    }
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "rapport-pfe", "figures")
os.makedirs(OUT, exist_ok=True)


def save(fig, name: str) -> None:
    path = os.path.join(OUT, name)
    fig.savefig(path)
    plt.close(fig)
    print("wrote", path)


def box(ax, xy, w, h, text, *, fc=IRLIGHT, ec=IRBLUE, lw=1.6, fs=9,
        tc="#15314f", rounded=0.06, bold=False, style="round"):
    x, y = xy
    pad = "round,pad=0.02,rounding_size={:.3f}".format(rounded) if style == "round" else "square,pad=0.02"
    p = FancyBboxPatch(
        (x, y), w, h, boxstyle=pad, fc=fc, ec=ec, lw=lw, mutation_aspect=1.0,
        zorder=2,
    )
    ax.add_patch(p)
    ax.text(
        x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
        color=tc, zorder=3, fontweight="bold" if bold else "normal",
    )
    return (x, y, w, h)


def arrow(ax, p0, p1, *, color=IRBLUE, lw=1.6, style="-|>", rad=0.0,
          ls="-"):
    a = FancyArrowPatch(
        p0, p1, arrowstyle=style, mutation_scale=12, color=color, lw=lw,
        connectionstyle=f"arc3,rad={rad}", zorder=1, linestyle=ls,
    )
    ax.add_patch(a)


# ==========================================================================
# 1. Seven-stage pipeline
# ==========================================================================
def fig_pipeline():
    fig, ax = plt.subplots(figsize=(11.0, 3.1))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 30)
    ax.axis("off")

    labels = [
        ("A", "Sink\nLocator"),
        ("B", "Slicer"),
        ("C", "Recon-\nstructor"),
        ("D", "Intent\nParser"),
        ("E", r"Binder ($\varphi$)"),
        ("F", "Synth-\nesiser"),
        ("G", "Validator"),
    ]
    n = len(labels)
    w, h = 11.0, 9.0
    gap = (100 - n * w) / (n + 1)
    y = 12.5
    centers = []
    for i, (tag, name) in enumerate(labels):
        x = gap + i * (w + gap)
        fc = IRLIGHT
        ec = IRBLUE
        if tag in ("D", "E"):
            fc = "#E3F1E4"
            ec = IRGREEN
        box(ax, (x, y), w, h, f"{tag}\n{name}", fc=fc, ec=ec, fs=9, bold=True,
            tc="#15314f" if tag not in ("D", "E") else "#1c4a20")
        centers.append((x + w / 2, x, x + w))
        if i > 0:
            prev = gap + (i - 1) * (w + gap)
            arrow(ax, (prev + w, y + h / 2), (x, y + h / 2))

    # IO annotations
    ax.text(centers[0][0], y + h + 3.0, "SARIF finding", ha="center",
            fontsize=8, style="italic", color=IRGRAY)
    ax.text(centers[3][0], y + h + 3.0, r"IAM $(G,H,C,\Sigma)$", ha="center",
            fontsize=8, style="italic", color=IRGRAY)
    ax.text(centers[6][0], y + h + 3.0, "certified patch", ha="center",
            fontsize=8, style="italic", color=IRGRAY)
    ax.text(centers[4][0], y - 3.2, r"accept / $\bot$", ha="center",
            fontsize=8, style="italic", color=IRGRAY)

    # dashed conceptual-core box around D,E
    x0 = centers[3][1] - 1.2
    x1 = centers[4][2] + 1.2
    ax.add_patch(FancyBboxPatch(
        (x0, y - 1.6), x1 - x0, h + 3.2, boxstyle="round,pad=0.1",
        fc="none", ec=IRGREEN, lw=1.4, ls=(0, (5, 3)), zorder=0))
    ax.text((x0 + x1) / 2, y - 6.0, "conceptual core: intent reconstruction + binding",
            ha="center", fontsize=8, color=IRGREEN, style="italic")

    save(fig, "fig_pipeline.pdf")


# ==========================================================================
# 2. System architecture / component breakdown
# ==========================================================================
def fig_architecture():
    fig, ax = plt.subplots(figsize=(10.6, 6.6))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Layer bands
    def band(y, hgt, label, color):
        ax.add_patch(FancyBboxPatch((2, y), 96, hgt, boxstyle="round,pad=0.2",
                                    fc=color, ec="none", zorder=0, alpha=0.35))
        ax.text(4, y + hgt - 3.2, label, fontsize=9, color=IRGRAY,
                style="italic", ha="left", va="top")

    band(80, 16, "Input layer", "#dfe9f3")
    band(40, 36, "Core pipeline (core/)", "#e6f0e7")
    band(20, 16, "Knowledge & proofs", "#f3eede")
    band(2, 14, "Interfaces", "#efe6ee")

    # input layer
    box(ax, (8, 84), 26, 9, "SAST detectors\nSemgrep / CodeQL", fc="#dfe9f3",
        ec=IRBLUE, fs=8)
    box(ax, (40, 84), 24, 9, "ingest/\nSARIF normaliser", fc="#dfe9f3",
        ec=IRBLUE, fs=8)
    box(ax, (70, 84), 24, 9, "Unified finding\nschema", fc="#dfe9f3",
        ec=IRBLUE, fs=8)
    arrow(ax, (34, 88.5), (40, 88.5))
    arrow(ax, (64, 88.5), (70, 88.5))

    # core pipeline modules
    core = [
        ("slicer/", 7, 64), ("recon/", 26, 64), ("parsers/", 45, 64),
        ("disambig/", 64, 64), ("iam/", 83, 64),
        ("phi/ + binder/", 7, 48), ("rewriter/", 33, 48),
        ("validator/", 55, 48), ("pipeline/", 78, 48),
    ]
    for name, x, y in core:
        box(ax, (x, y), 15, 10, name, fc="#e6f0e7", ec=IRGREEN, fs=8)
    # flow arrows along core row 1
    row1 = [(7, 64), (26, 64), (45, 64), (64, 64), (83, 64)]
    for (x0, _), (x1, _) in zip(row1, row1[1:]):
        arrow(ax, (x0 + 15, 69), (x1, 69), color=IRGREEN)
    arrow(ax, (90, 64), (90, 58), color=IRGREEN, rad=0.0)
    arrow(ax, (90, 58), (22, 58), color=IRGREEN)
    arrow(ax, (14.5, 58), (14.5, 58.0), color=IRGREEN)
    # row 2 flow
    row2 = [(7, 48), (33, 48), (55, 48), (78, 48)]
    for (x0, _), (x1, _) in zip(row2, row2[1:]):
        arrow(ax, (x0 + 15, 53), (x1, 53), color=IRGREEN)

    # knowledge layer
    box(ax, (8, 22), 26, 10, "binders/\n11 YAML catalogs", fc="#f3eede",
        ec=IRAMBER, fs=8)
    box(ax, (40, 22), 24, 10, "schemas/\nbinder.schema.json", fc="#f3eede",
        ec=IRAMBER, fs=8)
    box(ax, (70, 22), 24, 10, "formal/\nLean 4 proofs", fc="#f3eede",
        ec=IRAMBER, fs=8)
    arrow(ax, (16, 48), (18, 32), color=IRAMBER, ls="--", style="-|>")
    arrow(ax, (60, 48), (55, 32), color=IRAMBER, ls="--", style="-|>")

    # interface layer
    box(ax, (8, 4), 40, 9, "cli.py  (Typer: scan/plan/patch/validate/pipeline)",
        fc="#efe6ee", ec="#7a3d72", fs=8)
    box(ax, (54, 4), 40, 9, "scripts/ harnesses\n(run_snippet_tests, run_project_tests)",
        fc="#efe6ee", ec="#7a3d72", fs=8)

    save(fig, "fig_architecture.pdf")


# ==========================================================================
# 3. Semantic Intent Graph (SIG) with typed holes
# ==========================================================================
def fig_iam_sig():
    fig, ax = plt.subplots(figsize=(10.2, 5.8))
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 100)
    ax.axis("off")

    ax.text(60, 97,
            r"Query:  SELECT id FROM users WHERE name = $\langle$h1$\rangle$ AND role = $\langle$h2$\rangle$",
            ha="center", fontsize=9, color=IRGRAY, style="italic")

    def node(x, y, t, fc=IRLIGHT, ec=IRBLUE, fs=8.5, w=15, h=7):
        return box(ax, (x - w / 2, y - h / 2), w, h, t, fc=fc, ec=ec, fs=fs)

    # tree (root)
    node(50, 86, "Select", fc="#dfe9f3")
    node(18, 68, "Columns", fc="#dfe9f3")
    node(44, 68, "From", fc="#dfe9f3")
    node(82, 68, "Where", fc="#dfe9f3")
    node(18, 50, "id", fc="#ffffff")
    node(44, 50, "users", fc="#ffffff")
    node(82, 50, "And", fc="#dfe9f3")

    # two equality predicates under And, well separated
    node(64, 32, "Eq", fc="#dfe9f3")
    node(100, 32, "Eq", fc="#dfe9f3")
    node(54, 13, "name", fc="#ffffff", w=14)
    node(74, 13, "hole h1\nvalue:string", fc="#E3F1E4", ec=IRGREEN, fs=7.3,
         w=18)
    node(90, 13, "role", fc="#ffffff", w=14)
    node(110, 13, "hole h2\nvalue:enum", fc="#E3F1E4", ec=IRGREEN, fs=7.3,
         w=18)

    edges = [
        ((50, 82.5), (18, 71.5)), ((50, 82.5), (44, 71.5)),
        ((50, 82.5), (82, 71.5)),
        ((18, 64.5), (18, 53.5)), ((44, 64.5), (44, 53.5)),
        ((82, 64.5), (82, 53.5)),
        ((82, 46.5), (64, 35.5)), ((82, 46.5), (100, 35.5)),
        ((64, 28.5), (54, 16.5)), ((64, 28.5), (74, 16.5)),
        ((100, 28.5), (90, 16.5)), ((100, 28.5), (110, 16.5)),
    ]
    for p0, p1 in edges:
        arrow(ax, p0, p1, color=IRGRAY, lw=1.2, style="-")

    leg = [
        Patch(fc="#dfe9f3", ec=IRBLUE, label="syntax node"),
        Patch(fc="#ffffff", ec=IRBLUE, label="literal / identifier"),
        Patch(fc="#E3F1E4", ec=IRGREEN, label="typed hole (data position)"),
    ]
    ax.legend(handles=leg, loc="lower left", fontsize=8, frameon=True,
              bbox_to_anchor=(0.0, 0.0))
    save(fig, "fig_iam_sig.pdf")


# ==========================================================================
# 4. Data relocation: grammar layer vs protocol layer
# ==========================================================================
def fig_dataflow():
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.2))
    for ax in axes:
        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)
        ax.axis("off")

    # BEFORE
    ax = axes[0]
    ax.set_title("Before: data inside the grammar (vulnerable)",
                 fontsize=10, color=IRRED)
    box(ax, (10, 74), 80, 14, "untrusted input  (name)", fc="#fbe7e7",
        ec=IRRED, fs=9, bold=True)
    arrow(ax, (50, 74), (50, 62), color=IRRED, lw=2)
    box(ax, (10, 46), 80, 16,
        'string concat:\n"... WHERE name = \'" + name + "\'"',
        fc="#fdf2e7", ec=IRAMBER, fs=8.5)
    arrow(ax, (50, 46), (50, 34), color=IRRED, lw=2)
    box(ax, (10, 16), 80, 18, "interpreter LEXER / PARSER\n(name is lexed as SQL syntax)",
        fc="#fbe7e7", ec=IRRED, fs=9)
    ax.text(50, 6, "attacker bytes become code", ha="center", fontsize=8.5,
            color=IRRED, style="italic")

    # AFTER
    ax = axes[1]
    ax.set_title("After: data on the protocol layer (sound)",
                 fontsize=10, color=IRGREEN)
    box(ax, (10, 74), 80, 14, "untrusted input  (name)", fc="#E3F1E4",
        ec=IRGREEN, fs=9, bold=True)
    arrow(ax, (50, 74), (50, 62), color=IRGREEN, lw=2)
    box(ax, (10, 46), 80, 16,
        'parameter bind:\nps.setString(1, name)',
        fc="#E3F1E4", ec=IRGREEN, fs=8.5)
    arrow(ax, (30, 46), (30, 34), color=IRGRAY, lw=2, ls="--")
    arrow(ax, (70, 46), (70, 34), color=IRGREEN, lw=2)
    box(ax, (8, 16), 44, 18, "PARSER\nskeleton only:\n\"... WHERE name = ?\"",
        fc="#dfe9f3", ec=IRBLUE, fs=8.5)
    box(ax, (56, 16), 36, 18, "PROTOCOL\nparameter channel\n(opaque datum)",
        fc="#E3F1E4", ec=IRGREEN, fs=8.5)
    ax.text(50, 6, "attacker bytes never lexed as code", ha="center",
            fontsize=8.5, color=IRGREEN, style="italic")

    save(fig, "fig_dataflow.pdf")


# ==========================================================================
# 5. Five-gate validation flowchart
# ==========================================================================
def fig_gates():
    fig, ax = plt.subplots(figsize=(10.8, 3.3))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 30)
    ax.axis("off")

    gates = ["1. Compile", "2. Regression", "3. Structural",
             "4. Re-SAST", "5. Differential"]
    n = len(gates)
    w, h = 13.0, 9.0
    gap = (88 - n * w) / (n + 1)
    y = 14
    box(ax, (1, y + 1), 7, h - 2, "patch", fc="#f3eede", ec=IRAMBER, fs=8)
    prevx = 8
    for i, g in enumerate(gates):
        x = 10 + gap + i * (w + gap)
        ec = IRBLUE if i != 2 else IRGREEN
        fc = IRLIGHT if i != 2 else "#E3F1E4"
        box(ax, (x, y), w, h, g, fc=fc, ec=ec, fs=8.2, bold=(i == 2))
        arrow(ax, (prevx, y + h / 2), (x, y + h / 2))
        # fail path down
        arrow(ax, (x + w / 2, y), (x + w / 2, 4), color=IRRED, lw=1.2,
              ls="--")
        prevx = x + w
    ax.text(50, 2.0, r"any gate fails $\Rightarrow$ reject (no accept)",
            ha="center", fontsize=8, color=IRRED, style="italic")
    box(ax, (92, y + 1), 7, h - 2, "accept", fc="#E3F1E4", ec=IRGREEN, fs=8,
        bold=True)
    arrow(ax, (prevx, y + h / 2), (92, y + h / 2), color=IRGREEN)
    ax.text(10 + gap + 2 * (w + gap) + w / 2, y + h + 2.5,
            "certifies Thm. structural soundness", ha="center", fontsize=7.5,
            color=IRGREEN, style="italic")
    save(fig, "fig_gates.pdf")


# ==========================================================================
# 6. Sequence diagram of a repair
# ==========================================================================
def fig_sequence():
    fig, ax = plt.subplots(figsize=(10.4, 6.2))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    actors = ["Detector", "Slicer/\nRecon", "Parser\n(IAM)", r"Binder $\varphi$",
              "Synth", "Validator"]
    xs = np.linspace(10, 90, len(actors))
    top = 94
    bot = 8
    for x, a in zip(xs, actors):
        box(ax, (x - 7, top), 14, 6, a, fc=IRLIGHT, ec=IRBLUE, fs=8)
        ax.plot([x, x], [top, bot], color=IRGRAY, lw=1.0, ls=(0, (4, 3)),
                zorder=0)

    msgs = [
        (0, 1, "SARIF finding", 86),
        (1, 2, "parameterised template", 76),
        (2, 3, r"IAM $(G,H,C,\Sigma)$", 66),
        (3, 4, "patch plan (setters, guards)", 56),
        (4, 5, "patched AST + diff", 46),
        (5, 5, "5 gates", 36),
    ]
    for a, b, label, y in msgs:
        if a == b:
            ax.annotate("", xy=(xs[a] + 9, y - 3), xytext=(xs[a], y),
                        arrowprops=dict(arrowstyle="-|>", color=IRGREEN))
            ax.annotate("", xy=(xs[a], y - 6), xytext=(xs[a] + 9, y - 3),
                        arrowprops=dict(arrowstyle="-|>", color=IRGREEN))
            ax.text(xs[a] + 10, y - 3, label, fontsize=8, va="center",
                    color=IRGREEN)
        else:
            arrow(ax, (xs[a], y), (xs[b], y), color=IRBLUE)
            ax.text((xs[a] + xs[b]) / 2, y + 1.6, label, ha="center",
                    fontsize=8, color="#15314f")

    # abstention note
    ax.text(50, 24,
            r"At any arrow: if a proof obligation cannot be discharged, the stage returns $\bot$ with a reason.",
            ha="center", fontsize=8, color=IRRED, style="italic")
    box(ax, (72, 12), 24, 7, "accept  /  reject", fc="#E3F1E4", ec=IRGREEN,
        fs=8.5, bold=True)
    save(fig, "fig_sequence.pdf")


# ==========================================================================
# 7. Functional fix rate (M2) vs baselines
# ==========================================================================
def fig_m2_baselines():
    fig, ax = plt.subplots(figsize=(7.6, 4.0))
    tools = ["IR-SAM", "Semgrep\nautofix", "CodeQL\n+GPT-4", "VulRepair",
             "SeqTrans", "ChatRepair", "LLM\n0-shot"]
    vals = [0.80, 0.20, 0.15, 0.05, 0.05, 0.05, 0.00]
    colors = [IRGREEN] + [IRBLUE] * 6
    bars = ax.bar(tools, vals, color=colors, edgecolor="#1b3a5c", width=0.62)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Functional fix rate (M2)")
    ax.yaxis.grid(True, color="#cfd8e3", lw=0.7)
    ax.set_axisbelow(True)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.2f}",
                ha="center", fontsize=8.5)
    ax.tick_params(axis="x", labelsize=8.5)
    save(fig, "fig_m2_baselines.pdf")


# ==========================================================================
# 8. Detection per-CWE on OWASP Benchmark
# ==========================================================================
def fig_detection_bench():
    fig, ax = plt.subplots(figsize=(7.8, 4.0))
    cwes = ["Overall", "CWE-89", "CWE-78", "CWE-90", "CWE-643"]
    P = [0.573, 0.556, 0.750, 0.0, 0.0]
    R = [0.180, 0.257, 0.071, 0.0, 0.0]
    F = [0.273, 0.352, 0.130, 0.0, 0.0]
    x = np.arange(len(cwes))
    wb = 0.26
    ax.bar(x - wb, P, wb, label="Precision", color=IRBLUE)
    ax.bar(x, R, wb, label="Recall", color=IRGREEN)
    ax.bar(x + wb, F, wb, label="F1", color=IRAMBER)
    ax.set_xticks(x)
    ax.set_xticklabels(cwes, fontsize=9)
    ax.set_ylim(0, 0.85)
    ax.set_ylabel("Score")
    ax.yaxis.grid(True, color="#cfd8e3", lw=0.7)
    ax.set_axisbelow(True)
    ax.legend(fontsize=8.5, ncol=3, loc="upper right")
    save(fig, "fig_detection_bench.pdf")


# ==========================================================================
# 9. Abstention reasons (138 OWASP Benchmark findings)
# ==========================================================================
def fig_abstention():
    fig, ax = plt.subplots(figsize=(8.2, 3.8))
    reasons = [
        "No connection var\nin local scope",
        "Already parameterised\n(placeholder ?)",
        "Non-DML grammar\n({call ...})",
        "Unsupported backend\n(java/shell)",
        "Unsupported\nquoting syntax",
    ]
    counts = [55, 54, 12, 12, 5]
    colors = [IRBLUE, IRGREEN, IRAMBER, IRGRAY, "#7a3d72"]
    bars = ax.barh(reasons[::-1], counts[::-1], color=colors[::-1],
                   edgecolor="#1b3a5c", height=0.62)
    ax.set_xlabel("Number of findings (of 138)")
    ax.xaxis.grid(True, color="#cfd8e3", lw=0.7)
    ax.set_axisbelow(True)
    for b, v in zip(bars, counts[::-1]):
        ax.text(v + 0.8, b.get_y() + b.get_height() / 2, str(v),
                va="center", fontsize=9)
    ax.set_xlim(0, 62)
    ax.tick_params(axis="y", labelsize=8.5)
    save(fig, "fig_abstention.pdf")


# ==========================================================================
# 10. Metrics radar: IR-SAM vs baselines (M1,M2,M3,M6 + inverted M4)
# ==========================================================================
def fig_metrics_radar():
    metrics = ["M1\napplic.", "M2\nfix rate", "M3\nequiv.",
               "1-M4\nno residual", "M6\nabst. prec."]
    series = {
        "IR-SAM": [0.80, 0.80, 1.00, 1.00, 1.00],
        "Semgrep-autofix": [0.20, 0.20, 0.20, 1.00, 0.00],
        "CodeQL+GPT-4": [0.15, 0.15, 0.15, 0.90, 0.00],
        "VulRepair": [0.05, 0.05, 0.05, 1.00, 1.00],
    }
    cols = {"IR-SAM": IRGREEN, "Semgrep-autofix": IRBLUE,
            "CodeQL+GPT-4": IRAMBER, "VulRepair": "#7a3d72"}
    N = len(metrics)
    ang = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    ang += ang[:1]
    fig, ax = plt.subplots(figsize=(6.4, 6.0), subplot_kw=dict(polar=True))
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(ang[:-1])
    ax.set_xticklabels(metrics, fontsize=8.5)
    ax.set_ylim(0, 1.05)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.5", "0.75", "1.0"], fontsize=7.5,
                       color=IRGRAY)
    for name, vals in series.items():
        v = vals + vals[:1]
        ax.plot(ang, v, color=cols[name], lw=1.8, label=name)
        ax.fill(ang, v, color=cols[name], alpha=0.10)
    ax.legend(loc="upper right", bbox_to_anchor=(1.28, 1.12), fontsize=8)
    save(fig, "fig_metrics_radar.pdf")


# ==========================================================================
# 11. Lean proof status
# ==========================================================================
def fig_lean_status():
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.8))

    ax = axes[0]
    cats = ["Closed\n(no sorry)", "Partial\n(trivial)", "Deferred\n(sorry)"]
    vals = [20, 8, 0]
    colors = [IRGREEN, IRAMBER, IRRED]
    bars = ax.bar(cats, vals, color=colors, edgecolor="#1b3a5c", width=0.6)
    ax.set_ylabel("Theorems / lemmas")
    ax.set_ylim(0, 24)
    ax.yaxis.grid(True, color="#cfd8e3", lw=0.7)
    ax.set_axisbelow(True)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.4, str(v), ha="center",
                fontsize=10)
    ax.set_title("Mechanisation status", fontsize=9.5)

    ax = axes[1]
    files = ["StringAlgebra", "Shell", "Soundness/Lemmas",
             "Soundness/SQL", "Soundness/Shell", "Soundness/Audit",
             "Soundness/Theorem"]
    closed = [3, 5, 2, 3, 4, 2, 4]
    partial = [0, 0, 0, 5, 0, 0, 0]
    y = np.arange(len(files))
    ax.barh(y, closed, color=IRGREEN, edgecolor="#1b3a5c", label="closed")
    ax.barh(y, partial, left=closed, color=IRAMBER, edgecolor="#1b3a5c",
            label="partial")
    ax.set_yticks(y)
    ax.set_yticklabels(files, fontsize=7.8)
    ax.invert_yaxis()
    ax.set_xlabel("count")
    ax.legend(fontsize=8, loc="lower right")
    ax.set_title("Per-module breakdown", fontsize=9.5)
    save(fig, "fig_lean_status.pdf")


# ==========================================================================
# 12. Controlled-tier guarantees summary
# ==========================================================================
def fig_summary():
    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    labels = ["Detection\nF1", "Patch\ncorrectness", "Abstention\nsoundness",
              "Residual-CWE\nrate"]
    vals = [1.0, 1.0, 1.0, 0.0]
    colors = [IRGREEN, IRGREEN, IRGREEN, IRGREEN]
    bars = ax.bar(labels, vals, color=colors, edgecolor="#1b3a5c", width=0.6)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Rate")
    ax.yaxis.grid(True, color="#cfd8e3", lw=0.7)
    ax.set_axisbelow(True)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}",
                ha="center", fontsize=10)
    save(fig, "fig_summary.pdf")


def main():
    fig_pipeline()
    fig_architecture()
    fig_iam_sig()
    fig_dataflow()
    fig_gates()
    fig_sequence()
    fig_m2_baselines()
    fig_detection_bench()
    fig_abstention()
    fig_metrics_radar()
    fig_lean_status()
    fig_summary()
    print("\nAll figures written to", OUT)


if __name__ == "__main__":
    main()
