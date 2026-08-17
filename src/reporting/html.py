"""
HTML report generator.

Wraps the Markdown report in a responsive, dark-mode styled HTML page.
Uses Jinja2 for templating and Python-Markdown for MD→HTML conversion.

Output is a self-contained single-file HTML with inline CSS.
No external CDN dependencies — works air-gapped inside the container.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader

from agent.planner import AgentResult

_SEVERITY_COLOR = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44bb44",
    "info":     "#4488ff",
    "unknown":  "#888888",
}

# ---------------------------------------------------------------------------
# Inline Jinja2 template — single-file, no external assets
# ---------------------------------------------------------------------------

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Pentest Report — {{ goal | truncate(60) }}</title>
  <style>
    :root {
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #30363d;
      --text:     #c9d1d9;
      --muted:    #8b949e;
      --accent:   #58a6ff;
      --critical: #ff4444;
      --high:     #ff8800;
      --medium:   #ffcc00;
      --low:      #44bb44;
      --info:     #4488ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      font-size: 14px;
      line-height: 1.6;
      padding: 2rem;
    }
    a { color: var(--accent); text-decoration: none; }
    h1 { font-size: 2rem; color: var(--accent); border-bottom: 1px solid var(--border);
         padding-bottom: .5rem; margin-bottom: 1.5rem; }
    h2 { font-size: 1.3rem; color: var(--accent); margin: 2rem 0 .75rem; }
    h3 { font-size: 1rem; color: var(--muted); margin: 1.5rem 0 .5rem; }
    .meta { display: flex; gap: 2rem; flex-wrap: wrap; margin-bottom: 2rem;
            padding: 1rem; background: var(--surface); border-radius: 8px;
            border: 1px solid var(--border); }
    .meta div { display: flex; flex-direction: column; }
    .meta .label { font-size: .75rem; color: var(--muted); text-transform: uppercase; }
    .meta .value { color: var(--text); font-weight: 600; }
    .summary-box { background: var(--surface); border: 1px solid var(--border);
                   border-radius: 8px; padding: 1rem; margin-bottom: 2rem;
                   white-space: pre-wrap; font-family: inherit; }
    /* Stat cards */
    .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
    .stat { background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: .75rem 1.25rem; text-align: center; }
    .stat .num { font-size: 1.8rem; font-weight: 700; }
    .stat .lbl { font-size: .75rem; color: var(--muted); }
    /* Severity badge */
    .badge {
      display: inline-block; padding: .2em .6em; border-radius: 4px;
      font-size: .75rem; font-weight: 700; text-transform: uppercase;
      color: #000;
    }
    .badge-critical { background: var(--critical); color: #fff; }
    .badge-high     { background: var(--high); color: #000; }
    .badge-medium   { background: var(--medium); color: #000; }
    .badge-low      { background: var(--low);  color: #000; }
    .badge-info     { background: var(--info);  color: #fff; }
    .badge-unknown  { background: #555;         color: #fff; }
    /* Tables */
    table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
    th { background: var(--surface); text-align: left; padding: .5rem .75rem;
         border-bottom: 2px solid var(--border); color: var(--muted);
         font-size: .8rem; text-transform: uppercase; }
    td { padding: .5rem .75rem; border-bottom: 1px solid var(--border);
         vertical-align: top; }
    tr:hover td { background: var(--surface); }
    code { background: var(--surface); padding: .1em .4em; border-radius: 4px;
           font-family: monospace; font-size: .9em; }
    /* Steps */
    .step { border: 1px solid var(--border); border-radius: 8px;
            margin-bottom: 1.5rem; overflow: hidden; }
    .step-header { background: var(--surface); padding: .75rem 1rem;
                   display: flex; align-items: center; gap: .75rem; }
    .step-num { background: var(--accent); color: #000; border-radius: 50%;
                width: 1.8rem; height: 1.8rem; display: flex; align-items: center;
                justify-content: center; font-weight: 700; font-size: .85rem; }
    .step-tool { font-weight: 700; color: var(--accent); font-family: monospace; }
    .step-reason { color: var(--muted); font-size: .85rem; }
    .step-body { padding: 1rem; }
    .step-summary { background: var(--surface); border-radius: 6px;
                    padding: .75rem; margin-bottom: .75rem; font-style: italic; }
    /* Footer */
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
             color: var(--muted); font-size: .8rem; text-align: center; }
  </style>
</head>
<body>

<h1>🔴 Penetration Test Report</h1>

<div class="meta">
  <div><span class="label">Generated</span><span class="value">{{ generated }}</span></div>
  <div><span class="label">Model</span><span class="value">{{ model }}</span></div>
  <div><span class="label">Steps</span><span class="value">{{ steps_taken }}</span></div>
  <div><span class="label">Goal</span><span class="value">{{ goal }}</span></div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat">
    <div class="num" style="color:var(--critical)">{{ critical_count }}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="stat">
    <div class="num" style="color:var(--high)">{{ high_count }}</div>
    <div class="lbl">High</div>
  </div>
  <div class="stat">
    <div class="num" style="color:var(--medium)">{{ medium_count }}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="stat">
    <div class="num" style="color:var(--low)">{{ low_count }}</div>
    <div class="lbl">Low</div>
  </div>
  <div class="stat">
    <div class="num">{{ port_count }}</div>
    <div class="lbl">Open Ports</div>
  </div>
  <div class="stat">
    <div class="num">{{ subdomain_count }}</div>
    <div class="lbl">Subdomains</div>
  </div>
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<pre class="summary-box">{{ final_summary }}</pre>

<!-- Open Ports -->
{% if all_ports %}
<h2>Open Ports</h2>
<table>
  <tr><th>Port/Proto</th><th>Service</th></tr>
  {% for p in all_ports %}
  <tr><td><code>{{ p }}</code></td><td></td></tr>
  {% endfor %}
</table>
{% endif %}

<!-- Subdomains -->
{% if all_subs %}
<h2>Discovered Subdomains ({{ all_subs|length }})</h2>
<table>
  <tr><th>Host</th></tr>
  {% for s in all_subs %}
  <tr><td><code>{{ s }}</code></td></tr>
  {% endfor %}
</table>
{% endif %}

<!-- Findings -->
{% if all_vulns %}
<h2>Vulnerabilities &amp; Findings</h2>
<table>
  <tr><th>Severity</th><th>Finding</th></tr>
  {% for v in all_vulns %}
  {% set sev = v.lower().split(']')[0].lstrip('[') if ']' in v else 'unknown' %}
  <tr>
    <td><span class="badge badge-{{ sev }}">{{ sev }}</span></td>
    <td>{{ v }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<!-- Step-by-step evidence -->
<h2>Step-by-Step Evidence</h2>
{% for step in steps %}
<div class="step">
  <div class="step-header">
    <div class="step-num">{{ step.step }}</div>
    <span class="step-tool">{{ step.tool_call.tool }}</span>
    <span class="step-reason">— {{ step.tool_call.reason }}</span>
  </div>
  <div class="step-body">
    <div class="step-summary">{{ step.summary }}</div>
    {% if step.tool_call.args %}
    <p><strong>Arguments:</strong>
    {% for k, v in step.tool_call.args.items() %}
      <code>{{ k }}={{ v }}</code>
    {% endfor %}
    </p>
    {% endif %}
    {% if step.found_ports %}
    <p><strong>Ports:</strong>
    {% for p in step.found_ports %}<code>{{ p }}</code> {% endfor %}
    </p>
    {% endif %}
    {% if step.found_subdomains %}
    <p><strong>Subdomains ({{ step.found_subdomains|length }}):</strong>
    {% for s in step.found_subdomains[:10] %}<code>{{ s }}</code> {% endfor %}
    {% if step.found_subdomains|length > 10 %}
      <em>+{{ step.found_subdomains|length - 10 }} more</em>
    {% endif %}
    </p>
    {% endif %}
    {% if step.found_vulns %}
    <p><strong>Findings:</strong></p>
    <ul>{% for v in step.found_vulns %}<li>{{ v }}</li>{% endfor %}</ul>
    {% endif %}
  </div>
</div>
{% endfor %}

<footer>Generated by RedTeam MCP &mdash; For authorised security testing only.</footer>
</body>
</html>
"""


def generate_html_report(result: AgentResult, author: str = "RedTeam MCP") -> str:
    """
    Render a full self-contained HTML pentest report from an AgentResult.
    Returns an HTML string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Aggregate
    all_ports: list[str] = []
    all_subs:  list[str] = []
    all_vulns: list[str] = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for step in result.steps:
        all_ports += step.found_ports
        all_subs  += step.found_subdomains
        all_vulns += step.found_vulns

    all_ports = list(dict.fromkeys(all_ports))
    all_subs  = list(dict.fromkeys(all_subs))
    all_vulns = list(dict.fromkeys(all_vulns))

    for v in all_vulns:
        for sev in ("critical", "high", "medium", "low"):
            if f"[{sev.upper()}]" in v.upper():
                counts[sev] += 1
                break

    env = Environment(loader=BaseLoader(), autoescape=True)
    tmpl = env.from_string(_TEMPLATE)
    return tmpl.render(
        generated=now,
        goal=result.goal,
        model=result.model,
        steps_taken=result.steps_taken,
        final_summary=result.final_summary,
        steps=result.steps,
        all_ports=all_ports,
        all_subs=all_subs,
        all_vulns=all_vulns,
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        port_count=len(all_ports),
        subdomain_count=len(all_subs),
        author=author,
    )
