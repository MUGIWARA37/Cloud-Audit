import csv
import datetime
import json
import argparse
from typing import Any, Dict, List, Optional

from src.config import POLICY_METADATA


def generate_html_report(findings: List[Dict[str, Any]], args: argparse.Namespace, report_path: str, history: Optional[List[Dict[str, Any]]] = None, include_history: bool = False) -> None:
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.datetime.now(datetime.UTC).strftime("%B %d, %Y")
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")
    policies_scanned = len(POLICY_METADATA)
    total_findings = len(findings)
    finding_cards = ""
    for i, f in enumerate(findings):
        sev = f["severity"].lower()
        icon = {
            "critical": "&#x26A0;",
            "high": "&#x2622;",
            "medium": "&#x25C6;",
            "low": "&#x2139;",
        }.get(sev, "&#x25CF;")
        finding_cards += f"""\n        <div class="finding-card">\n          <div class="finding-header">\n            <div class="finding-id">\n              <span class="cis-badge">{f["cis_id"]}</span>\n              <span class="status-pill sev-{sev}">{icon} {f["severity"]}</span>\n            </div>\n          </div>\n          <h3 class="finding-title">{f["title"]}</h3>\n          <div class="finding-resource">\n            <span class="resource-label">Affected Resource</span>\n            <code class="resource-value">{f["resource"]}</code>\n          </div>\n          <div class="finding-footer">\n            <span class="playbook-link">&#x1F4D6; Remediation playbook available</span>\n          </div>\n        </div>"""
    empty_state = '\n        <div class="empty-state">\n          <div class="empty-icon">&#x2705;</div>\n          <h3>All Clear</h3>\n          <p>No misconfigurations found at or above the selected severity threshold.</p>\n        </div>'
    sev_bar_data = []
    if critical_count:
        sev_bar_data.append(("critical", critical_count))
    if high_count:
        sev_bar_data.append(("high", high_count))
    if medium_count:
        sev_bar_data.append(("medium", medium_count))
    if low_count:
        sev_bar_data.append(("low", low_count))
    donut_segments = ""
    cumulative_pct: float = 0.0
    if total_findings > 0:
        for sev_class, count in sev_bar_data:
            pct = count / total_findings * 100
            offset = -cumulative_pct
            donut_segments += f'<circle class="donut-segment seg-{sev_class}" cx="21" cy="21" r="15.9155" fill="transparent" stroke-width="6" stroke-dasharray="{pct} {100 - pct}" stroke-dashoffset="{offset}"></circle>'
            cumulative_pct += pct
    bar_legend = ""
    legend_items = [
        ("critical", "Critical", critical_count),
        ("high", "High", high_count),
        ("medium", "Medium", medium_count),
        ("low", "Low", low_count),
    ]
    for sev_class, label, count in legend_items:
        if count > 0:
            bar_legend += f'\n            <div class="legend-item">\n              <span class="legend-dot dot-{sev_class}"></span>\n              <span class="legend-label">{label}</span>\n              <span class="legend-count">{count}</span>\n            </div>'
    domain_counts: Dict[str, int] = {}
    resource_counts: Dict[str, int] = {}
    for f in findings:
        domain = f.get("domain", "General")
        res = f.get("resource_type", "Unknown")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        resource_counts[res] = resource_counts.get(res, 0) + 1

    def generate_hz_bars(counts_dict: Dict[str, int]) -> str:
        if not counts_dict:
            return '<div class="hz-bar-row"><div class="hz-label"><span>No findings</span></div></div>'
        max_val = max(counts_dict.values())
        out_html = ""
        for name, count in sorted(
            counts_dict.items(), key=lambda x: x[1], reverse=True,
        ):
            pct = count / max_val * 100
            out_html += f'\n            <div class="hz-bar-row">\n              <div class="hz-label"><span>{name}</span> <span>{count}</span></div>\n              <div class="hz-track"><div class="hz-fill" style="width: {pct:.1f}%"></div></div>\n            </div>'
        return out_html

    domain_bars = generate_hz_bars(domain_counts)
    resource_bars = generate_hz_bars(resource_counts)
    history_json = json.dumps(history or [])
    history_html = ""
    if include_history:
        history_html = f"""\n  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n\n  <!-- ── Date Search Section ── -->\n  <section class="panel-section" style="margin-top: 24px; margin-bottom: 24px;">\n    <h2 class="sev-bar-title">&#x1F50D; Search History by Date</h2>\n    <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px;">\n      <input type="date" id="dateSearch" style="\n        padding: 8px 14px; border-radius: 6px; border: 1px solid var(--line);\n        background: var(--panel-raised); color: var(--parchment); font-family: var(--font-mono);\n        font-size: 14px; cursor: pointer;\n      ">\n      <button onclick="searchByDate()" style="\n        padding: 8px 18px; border-radius: 6px; border: 1px solid var(--brass);\n        background: rgba(176,141,87,0.15); color: var(--brass); font-weight: 600;\n        font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer;\n      ">Search</button>\n      <button onclick="resetSearch()" style="\n        padding: 8px 18px; border-radius: 6px; border: 1px solid var(--line);\n        background: transparent; color: var(--parchment-dim); font-weight: 600;\n        font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer;\n      ">Reset</button>\n    </div>\n    <div id="dateResult" style="\n      background: var(--panel-raised); border: 1px solid var(--line); border-radius: 8px;\n      padding: 16px; display: none;\n    ">\n      <div style="display: flex; gap: 24px; align-items: center; flex-wrap: wrap;">\n        <div style="flex: none; width: 160px; height: 160px; position: relative;">\n          <canvas id="dateDonutChart"></canvas>\n          <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; pointer-events: none;">\n            <span id="dateDonutTotal" style="font-family: var(--font-mono); font-size: 28px; font-weight: 600; color: var(--parchment); line-height: 1;"></span>\n            <span style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--brass-dim); margin-top: 4px;">Findings</span>\n          </div>\n        </div>\n        <div style="flex: 1; min-width: 200px;">\n          <h3 id="dateResultTitle" style="font-family: var(--font-display); font-size: 18px; font-weight: 500; color: var(--parchment); margin: 0 0 12px;"></h3>\n          <div id="dateResultStats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 10px;"></div>\n        </div>\n      </div>\n    </div>\n    <div id="dateNotFound" style="display: none; text-align: center; padding: 20px; color: var(--parchment-dim); font-size: 13px;">\n      &#x26A0; No scan data found for this date.\n    </div>\n  </section>\n\n  
  <section class="panel-section" style="margin-bottom: 24px; background: transparent; border: none; padding: 0; box-shadow: none;">
    <h2 class="sev-bar-title" style="margin-bottom: 16px;">&#x1F4C8; Advanced Analytics Dashboard</h2>
    <svg style="width:0; height:0; position:absolute;">
  <defs>
    <!-- Light gray hash pattern for normal bars -->
    <pattern id="hash-gray" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <rect width="8" height="8" fill="rgba(255, 255, 255, 0.05)" />
      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(255, 255, 255, 0.3)" stroke-width="1.5" />
    </pattern>
    <!-- Solid purple hash pattern for highlighted bar -->
    <pattern id="hash-purple" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <rect width="8" height="8" fill="#00D068" />
      <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(255, 255, 255, 0.5)" stroke-width="1.5" />
    </pattern>
    <!-- Area Chart Gradient (Purple fading to transparent) -->
    <linearGradient id="area-gradient" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#00D068" stop-opacity="0.8" />
      <stop offset="100%" stop-color="#00D068" stop-opacity="0.0" />
    </linearGradient>
  </defs>
</svg>
    <div class="dashboard">
  <!-- ROW 1 (2 Panels) -->
  <div class="row-1">
    
    <!-- PANEL 1: Vertical Bar Chart -->
    <div class="panel panel-wide">
      <svg viewBox="0 0 582 240">
        <!-- Horizontal Gridlines -->
        <line x1="40" y1="30" x2="550" y2="30" class="grid-line" />
        <line x1="40" y1="70" x2="550" y2="70" class="grid-line" />
        <line x1="40" y1="110" x2="550" y2="110" class="grid-line" />
        <line x1="40" y1="150" x2="550" y2="150" class="grid-line" />
        <line x1="40" y1="190" x2="550" y2="190" class="grid-line" />
        
        <!-- Y-Axis Numeric Scale (0-60) -->
        <text id="bar-y-4" x="30" y="34" text-anchor="end" class="axis-label">60</text>
        <text id="bar-y-3" x="30" y="74" text-anchor="end" class="axis-label">45</text>
        <text id="bar-y-2" x="30" y="114" text-anchor="end" class="axis-label">30</text>
        <text id="bar-y-1" x="30" y="154" text-anchor="end" class="axis-label">15</text>
        <text x="30" y="194" text-anchor="end" class="axis-label">0</text>

        <!-- Bar 1 -->
        <rect id="bar-rect-0" x="70" y="190" width="36" height="0" fill="url(#hash-gray)" stroke="rgba(255,255,255,0.4)" stroke-width="1" style="transition: all 0.5s ease" />
        <text id="bar-val-0" x="88" y="190" class="value-label">0</text>
        <text id="bar-lbl-0" x="88" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Bar 2 -->
        <rect id="bar-rect-1" x="150" y="190" width="36" height="0" fill="url(#hash-gray)" stroke="rgba(255,255,255,0.4)" stroke-width="1" style="transition: all 0.5s ease" />
        <text id="bar-val-1" x="168" y="190" class="value-label">0</text>
        <text id="bar-lbl-1" x="168" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Bar 3 (Selected / Purple) -->
        <rect id="bar-rect-2" x="230" y="190" width="36" height="0" fill="url(#hash-gray)" stroke="rgba(255,255,255,0.4)" stroke-width="1" style="transition: all 0.5s ease" />
        <text id="bar-val-2" x="248" y="190" class="value-label">0</text>
        <text id="bar-lbl-2" x="248" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Bar 4 -->
        <rect id="bar-rect-3" x="310" y="190" width="36" height="0" fill="url(#hash-gray)" stroke="rgba(255,255,255,0.4)" stroke-width="1" style="transition: all 0.5s ease" />
        <text id="bar-val-3" x="328" y="190" class="value-label">0</text>
        <text id="bar-lbl-3" x="328" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Bar 5 -->
        <rect id="bar-rect-4" x="390" y="190" width="36" height="0" fill="url(#hash-gray)" stroke="rgba(255,255,255,0.4)" stroke-width="1" style="transition: all 0.5s ease" />
        <text id="bar-val-4" x="408" y="190" class="value-label">0</text>
        <text id="bar-lbl-4" x="408" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Bar 6 -->
        <rect id="bar-rect-5" x="470" y="190" width="36" height="0" fill="url(#hash-purple)" stroke="#fff" stroke-width="2" style="transition: all 0.5s ease" />
        <text id="bar-val-5" x="488" y="190" class="value-label">0</text>
        <text id="bar-lbl-5" x="488" y="210" text-anchor="middle" class="axis-label highlight">-</text>
      </svg>
    </div>

    <!-- PANEL 2: Area Line Chart -->
    <div class="panel panel-wide">
      <svg viewBox="0 0 582 240">
        <!-- Faint Gridlines -->
        <line x1="40" y1="30" x2="550" y2="30" class="grid-line" />
        <line x1="40" y1="83" x2="550" y2="83" class="grid-line" />
        <line x1="40" y1="136" x2="550" y2="136" class="grid-line" />
        <line x1="40" y1="190" x2="550" y2="190" class="grid-line" />

        <!-- Y-Axis Labels -->
        <text id="area-y-3" x="30" y="34" text-anchor="end" class="axis-label">15k</text>
        <text id="area-y-2" x="30" y="87" text-anchor="end" class="axis-label">10k</text>
        <text id="area-y-1" x="30" y="140" text-anchor="end" class="axis-label">5k</text>
        <text x="30" y="194" text-anchor="end" class="axis-label">0</text>

        <!-- Filled Area Polygon -->
        <path id="area-path-filled" d="M 60 190 L 500 190 Z" fill="url(#area-gradient)" style="transition: all 0.5s ease" />
        <!-- Data Line -->
        <path id="area-path-line" d="M 60 190 L 500 190" fill="none" stroke="#00D068" stroke-width="3" style="transition: all 0.5s ease" />

        <!-- X Axis Labels -->
        <text id="area-lbl-0" x="60" y="210" text-anchor="middle" class="axis-label">-</text>
        <text id="area-lbl-1" x="170" y="210" text-anchor="middle" class="axis-label">-</text>
        <text id="area-lbl-2" x="280" y="210" text-anchor="middle" class="axis-label">-</text>
        <text id="area-lbl-3" x="390" y="210" text-anchor="middle" class="axis-label highlight">-</text>
        <text id="area-lbl-4" x="500" y="210" text-anchor="middle" class="axis-label">-</text>

        <!-- Data Point Markers -->
        <g id="area-points"></g>

        <!-- Emphasized Point & Target Ring -->
        <circle id="area-target-ring" cx="500" cy="190" r="9" fill="none" stroke="#00D068" stroke-width="2" style="transition: all 0.5s ease" />
        <circle id="area-target-pt" cx="500" cy="190" r="4" fill="#00D068" style="transition: all 0.5s ease" />

        <!-- Callout Label -->
        <rect id="area-callout-rect" x="470" y="160" width="60" height="22" rx="4" fill="#00D068" style="transition: all 0.5s ease" />
        <text id="area-callout-val" x="500" y="175" class="value-label" style="fill:#131E17; font-size: 11px; font-weight: bold; transition: all 0.5s ease">0</text>
      </svg>
    </div>
  </div>

  <!-- ROW 2 (3 Panels) -->
  <div class="row-2">
    
    <!-- PANEL 3: Donut Chart -->
    <div class="panel panel-square">
      <svg viewBox="0 0 382 348">
        <!-- Faint dashed guide ring outside donut -->
        <circle cx="191" cy="174" r="105" fill="none" stroke="rgba(0, 208, 104, 0.4)" stroke-width="1" stroke-dasharray="4 4" />
        
        <!-- Large bold percentage -->
        <text id="donut-center" x="191" y="186" text-anchor="middle" style="font-size: 38px; font-weight: bold; fill: #00D068;">0</text>

        <!-- Donut Segments (Simulated via SVG stroke-dasharray) -->
        <g fill="none" stroke-width="24" transform="rotate(-90 191 174)">
          <!-- Segment 1: Solid Purple -->
          <circle id="donut-critical" cx="191" cy="174" r="80" stroke="#00D068" stroke-dasharray="0 503" style="transition: all 1s ease"/>
          <!-- Segment 2: Light Lavender -->
          <circle id="donut-high" cx="191" cy="174" r="80" stroke="#00A653" stroke-dasharray="0 503" style="transition: all 1s ease"/>
          <!-- Segment 3: White Outline Only -->
          <circle id="donut-medlow" cx="191" cy="174" r="80" stroke="rgba(0,208,104,0.2)" stroke-dasharray="0 503" style="transition: all 1s ease"/>
        </g>

        <!-- Leader Lines & Labels (Top Right & Bottom Left) -->
        <!-- Top Right Label -->
        <polyline points="250,110 280,80 340,80" fill="none" stroke="#00D068" stroke-width="1" />
        <text id="donut-lbl-1" x="340" y="74" text-anchor="end" class="axis-label" style="fill: #00D068; font-weight: bold;">Critical</text>
        <text id="donut-val-1" x="340" y="94" text-anchor="end" class="axis-label">0</text>

        <!-- Bottom Left Label -->
        <polyline points="130,235 100,265 40,265" fill="none" stroke="#00D068" stroke-width="1" />
        <text id="donut-lbl-2" x="40" y="259" text-anchor="start" class="axis-label" style="fill: #00D068; font-weight: bold;">High</text>
        <text id="donut-val-2" x="40" y="279" text-anchor="start" class="axis-label">0</text>
      </svg>
    </div>

    <!-- PANEL 4: Radar Chart -->
    <div class="panel panel-square">
      <svg viewBox="0 0 382 348">
        <g transform="translate(191, 174)">
          <!-- Concentric Pentagon Gridlines -->
          <polygon points="0,-110 104,-34 65,89 -65,89 -104,-34" fill="none" stroke="rgba(0, 208, 104, 0.4)" stroke-width="1" />
          <polygon points="0,-73 69,-23 43,59 -43,59 -69,-23" fill="none" stroke="rgba(0, 208, 104, 0.4)" stroke-width="1" />
          <polygon points="0,-36 34,-11 21,29 -21,29 -34,-11" fill="none" stroke="rgba(0, 208, 104, 0.4)" stroke-width="1" />

          <!-- Axes lines -->
          <line x1="0" y1="0" x2="0" y2="-110" stroke="rgba(0, 208, 104, 0.4)" />
          <line x1="0" y1="0" x2="104" y2="-34" stroke="rgba(0, 208, 104, 0.4)" />
          <line x1="0" y1="0" x2="65" y2="89" stroke="rgba(0, 208, 104, 0.4)" />
          <line x1="0" y1="0" x2="-65" y2="89" stroke="rgba(0, 208, 104, 0.4)" />
          <line x1="0" y1="0" x2="-104" y2="-34" stroke="rgba(0, 208, 104, 0.4)" />

          <!-- Center numeric value -->
          <text x="5" y="-4" class="axis-label" style="font-size:9px;">0</text>

          <!-- 5 Axis Tips Text Labels -->
          <text id="radar-lbl-0" x="0" y="-125" text-anchor="middle" class="axis-label">Storage</text>
          <text id="radar-lbl-1" x="120" y="-30" text-anchor="start" class="axis-label">Identity</text>
          <text id="radar-lbl-2" x="75" y="105" text-anchor="start" class="axis-label">Compute</text>
          <text id="radar-lbl-3" x="-75" y="105" text-anchor="end" class="axis-label">Network</text>
          <text id="radar-lbl-4" x="-120" y="-30" text-anchor="end" class="axis-label">General</text>

          <!-- Data Polygon (Semi-transparent purple) -->
          <polygon id="radar-poly" points="0,0 0,0 0,0 0,0 0,0" fill="rgba(0, 208, 104, 0.4)" stroke="#008744" stroke-width="2" style="transition: all 1s ease"/>
          <circle id="radar-pt-0" cx="0" cy="0" r="3" fill="#00D068" style="transition: all 1s ease"/>
          <circle id="radar-pt-1" cx="0" cy="0" r="3" fill="#00D068" style="transition: all 1s ease"/>
          <circle id="radar-pt-2" cx="0" cy="0" r="3" fill="#00D068" style="transition: all 1s ease"/>
          <circle id="radar-pt-3" cx="0" cy="0" r="3" fill="#00D068" style="transition: all 1s ease"/>
          <circle id="radar-pt-4" cx="0" cy="0" r="3" fill="#00D068" style="transition: all 1s ease"/>
        </g>
      </svg>
    </div>

    <!-- PANEL 5: Gauge Chart -->
    <div class="panel panel-square">
      <svg viewBox="0 0 382 348">
        <!-- Gauge Track Background (Segmented/Dashed dark purple) -->
        <path d="M 113 237 A 110 110 0 1 1 268 237" fill="none" stroke="rgba(0, 208, 104, 0.1)" stroke-width="16" stroke-dasharray="4 6" />
        <path d="M 113 237 A 110 110 0 1 1 268 237" fill="none" stroke="#008744" stroke-width="16" stroke-opacity="0.2" stroke-dasharray="4 6" />

        <!-- Filled Progress Arc (Solid bright purple, 83% full) -->
        <path id="gauge-arc" d="M 113 237 A 110 110 0 1 1 268 237" fill="none" stroke="#00D068" stroke-width="16" stroke-dasharray="0 518" style="transition: all 1.5s ease"/>

        <!-- Triangular Pointer Marking Exact Value -->
        <g id="gauge-pointer" transform="translate(191, 160) rotate(135)" style="transition: all 1.5s ease">
          <polygon points="-6,-95 6,-95 0,-115" fill="#00D068" />
        </g>

        <!-- Centered Text -->
        <text id="gauge-val" x="191" y="170" text-anchor="middle" style="font-size: 44px; font-weight: bold; fill: #00D068;">0%</text>
        <text x="191" y="200" text-anchor="middle" class="axis-label" style="text-transform: uppercase; letter-spacing: 0.1em;">System Health</text>
      </svg>
    </div>

  </div>
</div>
  </section>
\n\n  <script>\n    const historyData = {history_json};

    // ── Dynamic SVG Dashboard Injection ──
    (function() {{
      if (!historyData || historyData.length === 0) return;
      const latest = historyData[historyData.length - 1];
      
      // -- Panel 1: Bar Chart (Last 6 Days)
      const last6 = historyData.slice(-6);
      const maxTotal = Math.max(...last6.map(d => d.total), 1);
      const scale = 160 / maxTotal;
      
      // Update Y-Axis
      document.getElementById('bar-y-4').textContent = Math.round(maxTotal);
      document.getElementById('bar-y-3').textContent = Math.round(maxTotal * 0.75);
      document.getElementById('bar-y-2').textContent = Math.round(maxTotal * 0.5);
      document.getElementById('bar-y-1').textContent = Math.round(maxTotal * 0.25);
      
      last6.forEach((d, i) => {{
        const height = d.total * scale;
        const y = 190 - height;
        const rect = document.getElementById(`bar-rect-${{i}}`);
        if(rect) {{
          rect.setAttribute('height', height);
          rect.setAttribute('y', y);
        }}
        const val = document.getElementById(`bar-val-${{i}}`);
        if(val) {{
          val.textContent = d.total;
          val.setAttribute('y', y - 8);
        }}
        const lbl = document.getElementById(`bar-lbl-${{i}}`);
        if(lbl) {{
          const dateStr = d.date.split('-').slice(1).join('/');
          lbl.textContent = dateStr;
        }}
      }});
      
      // -- Panel 2: Area Line Chart (Last 9 Days)
      const last9 = historyData.slice(-9);
      if(last9.length > 0) {{
        const aMax = Math.max(...last9.map(d => d.total), 1);
        const aScale = 160 / aMax;
        
        // Update Y Axis
        document.getElementById('area-y-3').textContent = Math.round(aMax);
        document.getElementById('area-y-2').textContent = Math.round(aMax * 0.66);
        document.getElementById('area-y-1').textContent = Math.round(aMax * 0.33);
        
        const xStep = 440 / Math.max(1, last9.length - 1);
        let dStr = `M 60 190 `;
        let lStr = `M 60 ${{190 - last9[0].total * aScale}} `;
        
        const pointsGrp = document.getElementById('area-points');
        pointsGrp.innerHTML = '';
        
        last9.forEach((d, i) => {{
          const x = 60 + i * xStep;
          const y = 190 - d.total * aScale;
          dStr += `L ${{x}} ${{y}} `;
          if(i > 0) lStr += `L ${{x}} ${{y}} `;
          
          if(i === last9.length - 1) {{
            document.getElementById('area-target-ring').setAttribute('cx', x);
            document.getElementById('area-target-ring').setAttribute('cy', y);
            document.getElementById('area-target-pt').setAttribute('cx', x);
            document.getElementById('area-target-pt').setAttribute('cy', y);
            document.getElementById('area-callout-rect').setAttribute('x', x - 30);
            document.getElementById('area-callout-rect').setAttribute('y', y - 30);
            document.getElementById('area-callout-val').setAttribute('x', x);
            document.getElementById('area-callout-val').setAttribute('y', y - 15);
            document.getElementById('area-callout-val').textContent = d.total;
          }} else {{
            pointsGrp.innerHTML += `<circle cx="${{x}}" cy="${{y}}" r="4" fill="#00D068" />`;
          }}
          
          if(i % 2 === 0 && i / 2 < 5) {{
             const lbl = document.getElementById(`area-lbl-${{i/2}}`);
             if(lbl) lbl.textContent = d.date.split('-').slice(1).join('/');
          }}
        }});
        dStr += `L ${{60 + (last9.length-1)*xStep}} 190 Z`;
        
        document.getElementById('area-path-filled').setAttribute('d', dStr);
        document.getElementById('area-path-line').setAttribute('d', lStr);
      }}
      
      // -- Panel 3: Donut Chart
      const total = latest.total || 1; // avoid /0
      const critPct = latest.critical / total * 503;
      const highPct = latest.high / total * 503;
      const medLowPct = (latest.medium + latest.low) / total * 503;
      
      document.getElementById('donut-critical').setAttribute('stroke-dasharray', `${{critPct}} 503`);
      document.getElementById('donut-critical').setAttribute('stroke-dashoffset', `0`);
      
      document.getElementById('donut-high').setAttribute('stroke-dasharray', `${{highPct}} 503`);
      document.getElementById('donut-high').setAttribute('stroke-dashoffset', `-${{critPct}}`);
      
      document.getElementById('donut-medlow').setAttribute('stroke-dasharray', `${{medLowPct}} 503`);
      document.getElementById('donut-medlow').setAttribute('stroke-dashoffset', `-${{critPct + highPct}}`);
      
      document.getElementById('donut-center').textContent = Math.round((latest.critical + latest.high) / total * 100) + '%';
      
      document.getElementById('donut-val-1').textContent = latest.critical;
      document.getElementById('donut-val-2').textContent = latest.high;
      
      // -- Panel 4: Radar Chart
      // Map Domains: Storage, Identity, Compute, Network, General
      const domains = {{ Storage:0, Identity:0, Compute:0, Network:0, General:0 }};
      if(latest.findings) {{
        latest.findings.forEach(f => {{
          if(domains[f.domain] !== undefined) domains[f.domain]++;
          else domains.General++;
        }});
      }}
      const radarVals = [domains.Storage, domains.Identity, domains.Compute, domains.Network, domains.General];
      const rMax = Math.max(...radarVals, 1);
      
      // Angles for 5 points: -90, -18, 54, 126, 198
      const angles = [-90, -18, 54, 126, 198];
      let rPoints = '';
      radarVals.forEach((val, i) => {{
        const rad = val / rMax * 110;
        const theta = angles[i] * Math.PI / 180;
        const x = Math.round(rad * Math.cos(theta));
        const y = Math.round(rad * Math.sin(theta));
        rPoints += `${{x}},${{y}} `;
        document.getElementById(`radar-pt-${{i}}`).setAttribute('cx', x);
        document.getElementById(`radar-pt-${{i}}`).setAttribute('cy', y);
      }});
      document.getElementById('radar-poly').setAttribute('points', rPoints.trim());
      
      // -- Panel 5: Gauge Chart (Health Score)
      // Score = 100 - min(total, 100)
      const health = Math.max(0, 100 - latest.total);
      document.getElementById('gauge-val').textContent = health + '%';
      
      const arcLen = health / 100 * 518;
      document.getElementById('gauge-arc').setAttribute('stroke-dasharray', `${{arcLen}} 518`);
      
      const angle = -135 + (health / 100 * 270);
      document.getElementById('gauge-pointer').setAttribute('transform', `translate(191, 160) rotate(${{angle}})`);

    }})();
\n\n    \n\n    // ── Date Search: Doughnut + Stats ──\n    let dateDonutInstance = null;\n\n    function searchByDate() {{\n      const input = document.getElementById('dateSearch').value;\n      if (!input) return;\n      const entry = historyData.find(d => d.date === input);\n      const resultDiv = document.getElementById('dateResult');\n      const notFound = document.getElementById('dateNotFound');\n\n      if (!entry) {{\n        resultDiv.style.display = 'none';\n        notFound.style.display = 'block';\n        return;\n      }}\n      notFound.style.display = 'none';\n      resultDiv.style.display = 'block';\n\n      document.getElementById('dateResultTitle').textContent = 'Scan Results for ' + entry.date;\n      document.getElementById('dateDonutTotal').textContent = entry.total;\n\n      const statsHtml =\n        '<div style="text-align:center;"><span style="font-family:var(--font-mono);font-size:24px;font-weight:600;color:#00D068;">' + entry.critical + '</span><div style="font-size:10px;color:var(--brass-dim);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;">Critical</div></div>' +\n        '<div style="text-align:center;"><span style="font-family:var(--font-mono);font-size:24px;font-weight:600;color:#00A653;">' + entry.high + '</span><div style="font-size:10px;color:var(--brass-dim);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;">High</div></div>' +\n        '<div style="text-align:center;"><span style="font-family:var(--font-mono);font-size:24px;font-weight:600;color:#008744;">' + entry.medium + '</span><div style="font-size:10px;color:var(--brass-dim);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;">Medium</div></div>' +\n        '<div style="text-align:center;"><span style="font-family:var(--font-mono);font-size:24px;font-weight:600;color:#8BA895;">' + entry.low + '</span><div style="font-size:10px;color:var(--brass-dim);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;">Low</div></div>';\n      document.getElementById('dateResultStats').innerHTML = statsHtml;

      if (entry.findings && entry.findings.length > 0) {{
        let cardsHtml = '<h3 style="font-family:var(--font-display);font-size:14px;color:var(--parchment);margin-bottom:12px;border-bottom:1px solid var(--line);padding-bottom:8px;">Detailed Findings</h3>';
        entry.findings.forEach(f => {{
          let sev = f.severity.toLowerCase();
          let icon = sev === 'critical' ? '&#x26A0;' : sev === 'high' ? '&#x2622;' : sev === 'medium' ? '&#x25C6;' : '&#x2139;';
          cardsHtml += `
            <div class="finding-card" style="margin-bottom: 8px; padding: 12px;">
              <div class="finding-header">
                <div class="finding-id">
                  <span class="cis-badge">${{f.cis_id}}</span>
                  <span class="status-pill sev-${{sev}}">${{icon}} ${{f.severity}}</span>
                </div>
                <div style="font-size: 10px; color: var(--brass-dim); font-family: var(--font-mono);">${{entry.timestamp}}</div>
              </div>
              <h3 class="finding-title" style="margin: 8px 0 8px; font-size: 13px;">${{f.title}}</h3>
              <div class="finding-resource" style="padding: 8px 10px; margin-bottom: 0;">
                <span class="resource-label" style="font-size: 9px;">Affected Resource</span>
                <code class="resource-value" style="font-size: 11.5px;">${{f.resource}}</code>
              </div>
            </div>
          `;
        }});
        document.getElementById('dateFindingsContainer').innerHTML = cardsHtml;
      }} else {{
        document.getElementById('dateFindingsContainer').innerHTML = '<div style="color:var(--parchment-dim);font-size:12px;text-align:center;padding:20px;">No detailed findings recorded for this date.</div>';
      }}
\n\n      // Destroy previous doughnut if it exists\n      if (dateDonutInstance) dateDonutInstance.destroy();\n      const ctx = document.getElementById('dateDonutChart').getContext('2d');\n      dateDonutInstance = new Chart(ctx, {{\n        type: 'doughnut',\n        data: {{\n          labels: ['Critical', 'High', 'Medium', 'Low'],\n          datasets: [{{\n            data: [entry.critical, entry.high, entry.medium, entry.low],\n            backgroundColor: ['#00D068', '#00A653', '#008744', '#8BA895'],\n            borderColor: '#131E17',\n            borderWidth: 2\n          }}]\n        }},\n        options: {{\n          responsive: true,\n          maintainAspectRatio: true,\n          cutout: '65%',\n          plugins: {{ legend: {{ display: false }} }}\n        }}\n      }});\n    }}\n\n    function resetSearch() {{\n      document.getElementById('dateSearch').value = '';\n      document.getElementById('dateResult').style.display = 'none';\n      document.getElementById('dateNotFound').style.display = 'none';\n      if (dateDonutInstance) {{ dateDonutInstance.destroy(); dateDonutInstance = null; }}\n    }}\n  </script>\n"""
    html = f"""<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>Cloud Audit Report — {args.target_environment}</title>\n<link rel="preconnect" href="https://fonts.googleapis.com">\n<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,420;9..144,500;9..144,600&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">\n<style>\n  :root {{\n    --ink: #0B120E;\n    --panel: #131E17;\n    --panel-raised: #1A291F;\n    --line: #294031;\n    --parchment: #F4F7F6;\n    --parchment-dim: #8BA895;\n    --brass: #00A653;\n    --brass-dim: #8BA895;\n    --ember: #00D068;\n    --ember-bright: #00D068;\n    --moss: #00A653;\n    --moss-bright: #008744;\n    --gold: #00A653;\n    --chestnut: #00D068;\n    --font-display: 'Fraunces', serif;\n    --font-body: 'IBM Plex Sans', -apple-system, sans-serif;\n    --font-mono: 'IBM Plex Mono', ui-monospace, monospace;\n  }}\n  *, *::before, *::after {{ box-sizing: border-box; }}\n  html, body {{ margin: 0; padding: 0; }}\n  body {{\n    background:\n      radial-gradient(1200px 600px at 50% -10%, rgba(0, 135, 68, 0.05), transparent 60%),\n      var(--ink);\n    color: var(--parchment);\n    font-family: var(--font-body);\n    -webkit-font-smoothing: antialiased;\n    min-height: 100vh;\n  }}\n  .report {{ max-width: 1100px; margin: 0 auto; padding: 32px 28px 64px; }}\n  /* ── header ── */\n  .report-header {{\n    display: flex; align-items: center; justify-content: space-between;\n    padding-bottom: 20px; margin-bottom: 28px;\n    border-bottom: 1px solid var(--line);\n    flex-wrap: wrap; gap: 16px;\n  }}\n  .brand {{ display: flex; align-items: center; gap: 14px; }}\n  .brand svg {{ width: 40px; height: 40px; flex: none; }}\n  .brand-name {{\n    font-family: var(--font-display); font-weight: 600; font-size: 20px;\n    letter-spacing: 0.04em; color: var(--parchment); display: block;\n  }}\n  .brand-sub {{ font-size: 12px; color: var(--parchment-dim); letter-spacing: 0.02em; }}\n  .header-meta {{ display: flex; gap: 28px; }}\n  .meta-item {{ text-align: right; }}\n  .meta-label {{\n    display: block; font-size: 10px; text-transform: uppercase;\n    letter-spacing: 0.12em; color: var(--brass-dim); margin-bottom: 3px;\n  }}\n  .meta-value {{ font-family: var(--font-mono); font-size: 15px; color: var(--parchment); }}\n  /* ── stat cards ── */\n  .stats-grid {{\n    display: grid;\n    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));\n    gap: 14px; margin-bottom: 24px;\n  }}\n  .stat-card {{\n    background: var(--panel); border: 1px solid var(--line);\n    border-radius: 10px; padding: 18px 20px;\n    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);\n  }}\n  .stat-value {{\n    font-family: var(--font-mono); font-size: 32px; font-weight: 600;\n    color: var(--parchment); line-height: 1;\n  }}\n  .stat-label {{\n    font-size: 11px; color: var(--brass-dim); text-transform: uppercase;\n    letter-spacing: 0.08em; margin-top: 6px;\n  }}\n  .stat-value.val-critical {{ color: var(--chestnut); }}\n  .stat-value.val-high {{ color: var(--moss); }}\n  .stat-value.val-pass {{ color: var(--moss-bright); }}\n  /* ── severity chart ── */\n  .sev-chart-section {{\n    background: var(--panel); border: 1px solid var(--line);\n    border-radius: 10px; padding: 24px; margin-bottom: 24px;\n    display: flex; align-items: center; gap: 40px; flex-wrap: wrap;\n    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);\n  }}\n  .chart-wrapper {{\n    position: relative; width: 120px; height: 120px; flex: none;\n  }}\n  .donut-chart {{ width: 100%; height: 100%; transform: rotate(-90deg); }}\n  .donut-segment {{ transition: stroke-dasharray 1s ease, stroke-dashoffset 1s ease; }}\n  .donut-track {{ stroke: var(--line); }}\n  .chart-center {{\n    position: absolute; top: 0; left: 0; right: 0; bottom: 0;\n    display: flex; flex-direction: column; align-items: center; justify-content: center;\n  }}\n  .chart-total {{ font-family: var(--font-mono); font-size: 28px; font-weight: 600; color: var(--parchment); line-height: 1; }}\n  .chart-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--brass-dim); margin-top: 4px; }}\n  .seg-critical {{ stroke: var(--chestnut); background: var(--chestnut); }}\n  .seg-high {{ stroke: var(--moss); background: var(--moss); }}\n  .seg-medium {{ stroke: var(--moss-bright); background: var(--moss-bright); }}\n  .seg-low {{ stroke: var(--brass-dim); background: var(--brass-dim); }}\n  .seg-pass {{ stroke: var(--line); background: var(--line); }}\n  .legend-container {{ flex: 1; min-width: 200px; }}\n  .sev-bar-title {{\n    font-family: var(--font-body); font-weight: 600; font-size: 12px;\n    text-transform: uppercase; letter-spacing: 0.09em; color: var(--brass);\n    margin: 0 0 16px;\n  }}\n  .bar-legend {{\n    display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 16px;\n  }}\n  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 12px; }}\n  .legend-dot {{\n    width: 8px; height: 8px; border-radius: 50%; flex: none;\n  }}\n  .dot-critical {{ background: var(--chestnut); }}\n  .dot-high {{ background: var(--moss); }}\n  .dot-medium {{ background: var(--moss-bright); }}\n  .dot-low {{ background: var(--brass-dim); }}\n  .dot-pass {{ background: var(--line); }}\n  .legend-label {{ color: var(--parchment-dim); }}\n  .legend-count {{ font-family: var(--font-mono); font-weight: 600; color: var(--parchment); }}\n  /* ── horizontal bar graphs ── */\n  .chart-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; margin-bottom: 24px; }}\n  .panel-section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 24px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); }}\n  .hz-bar-row {{ margin-bottom: 14px; }}\n  .hz-bar-row:last-child {{ margin-bottom: 0; }}\n  .hz-label {{ font-size: 11px; color: var(--parchment-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; display: flex; justify-content: space-between; font-weight: 600; }}\n  .hz-track {{ height: 6px; background: var(--line); border-radius: 999px; overflow: hidden; }}\n  .hz-fill {{ height: 100%; background: var(--moss-bright); border-radius: 999px; transition: width 1s ease; }}\n  /* ── findings ── */\n  .findings-section {{\n    background: var(--panel); border: 1px solid var(--line);\n    border-radius: 10px; padding: 20px;\n    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);\n  }}\n  .section-title {{\n    font-family: var(--font-body); font-weight: 600; font-size: 12px;\n    text-transform: uppercase; letter-spacing: 0.09em; color: var(--brass);\n    margin: 0 0 16px;\n  }}\n  .finding-card {{\n    background: var(--panel-raised); border: 1px solid var(--line);\n    border-radius: 8px; padding: 16px 18px; margin-bottom: 12px;\n  }}\n  .finding-card:last-child {{ margin-bottom: 0; }}\n  .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}\n  .finding-id {{ display: flex; align-items: center; gap: 10px; }}\n  .cis-badge {{\n    font-family: var(--font-mono); font-size: 12px; font-weight: 600;\n    color: var(--parchment); background: rgba(139, 168, 149, 0.15);\n    padding: 3px 10px; border-radius: 4px; letter-spacing: 0.03em;\n  }}\n  .status-pill {{\n    display: inline-flex; align-items: center; gap: 5px;\n    font-size: 10.5px; font-weight: 600; text-transform: uppercase;\n    letter-spacing: 0.06em; padding: 4px 10px; border-radius: 999px;\n    white-space: nowrap;\n  }}\n  .sev-critical {{ background: rgba(0, 208, 104, 0.15); color: var(--chestnut); }}\n  .sev-high {{ background: rgba(0, 166, 83, 0.15); color: var(--moss); }}\n  .sev-medium {{ background: rgba(0, 135, 68, 0.15); color: var(--moss-bright); }}\n  .sev-low {{ background: rgba(139, 168, 149, 0.15); color: var(--brass-dim); }}\n  .finding-title {{\n    font-size: 14px; font-weight: 500; color: var(--parchment);\n    margin: 0 0 10px; line-height: 1.45;\n  }}\n  .finding-resource {{\n    display: flex; flex-direction: column; gap: 4px;\n    padding: 10px 12px; background: rgba(0,0,0,0.2);\n    border-radius: 6px; margin-bottom: 10px;\n  }}\n  .resource-label {{\n    font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;\n    color: var(--brass-dim);\n  }}\n  .resource-value {{\n    font-family: var(--font-mono); font-size: 13px; font-weight: 500;\n    color: var(--parchment); background: none; padding: 0;\n  }}\n  .finding-footer {{ font-size: 11.5px; color: var(--moss-bright); }}\n  .playbook-link {{ opacity: 0.8; }}\n  /* ── empty state ── */\n  .empty-state {{\n    text-align: center; padding: 48px 20px;\n  }}\n  .empty-icon {{ font-size: 40px; margin-bottom: 12px; }}\n  .empty-state h3 {{\n    font-family: var(--font-display); font-size: 20px; font-weight: 500;\n    color: var(--moss-bright); margin: 0 0 8px;\n  }}\n  .empty-state p {{ font-size: 13px; color: var(--parchment-dim); margin: 0; }}\n  /* ── footer ── */\n  .report-footer {{\n    margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--line);\n    font-size: 11px; color: var(--brass-dim);\n    display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;\n  }}\n  /* ── responsive ── */\n  @media (max-width: 640px) {{\n    .report {{ padding: 20px 16px 48px; }}\n    .stat-value {{ font-size: 26px; }}\n    .report-header {{ flex-direction: column; align-items: flex-start; }}\n    .header-meta {{ gap: 20px; }}\n    .meta-item {{ text-align: left; }}\n  }}\n  @media print {{\n    body {{ background: #fff; color: #111; }}\n    .report {{ padding: 0; }}\n    .stat-card, .sev-bar-section, .findings-section, .finding-card {{\n      background: #fafafa; border-color: #ddd;\n    }}\n    .status-pill {{ border: 1px solid currentColor; }}\n  }}\n
  

  

  /* 1. Layout Container Constraints */
  .dashboard {{
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 16px; /* Consistent vertical gap */
  }}

  .row-1 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }}

  .row-2 {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
  }}

  .panel {{
    background-color: #131E17;
    border: 1px solid rgba(0, 208, 104, 0.4);
    border-radius: 12px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 4px 24px rgba(0, 208, 104, 0.15);
  }}

  .panel-wide {{
    height: 240px; /* Wide rectangle (~2:1) */
  }}

  .panel-square {{
    height: 348px; /* ~1.45x taller than row 1 */
  }}

  svg {{
    width: 100%;
    height: 100%;
    display: block;
  }}

  /* Shared Text Styles */
  .axis-label {{ font-size: 11px; fill: #00D068; }}
  .axis-label.highlight {{ fill: #00D068; font-weight: bold; }}
  .value-label {{ font-size: 13px; font-weight: bold; fill: #00D068; text-anchor: middle; }}
  .grid-line {{ stroke: rgba(0, 208, 104, 0.4); stroke-width: 1; }}

</style>\n</head>\n<body>\n<div class="report">\n  <header class="report-header">\n    <div class="brand">\n      <svg viewBox="0 0 40 40" fill="none" aria-hidden="true">\n        <circle cx="20" cy="20" r="18" stroke="var(--brass)" stroke-width="1.4"/>\n        <path d="M12 28 Q16 14 20 18 T28 12" stroke="var(--ember-bright)" stroke-width="2.2" stroke-linecap="round" fill="none"/>\n        <circle cx="20" cy="20" r="3" fill="var(--ember-bright)" opacity="0.7"/>\n      </svg>\n      <div>\n        <span class="brand-name">CLOUD AUDIT</span>\n        <span class="brand-sub">Security Posture Report</span>\n      </div>\n    </div>\n    <div class="header-meta">\n      <div class="meta-item">\n        <span class="meta-label">Environment</span>\n        <span class="meta-value">{args.target_environment}</span>\n      </div>\n      <div class="meta-item">\n        <span class="meta-label">Framework</span>\n        <span class="meta-value">{args.compliance_framework.upper()}</span>\n      </div>\n      <div class="meta-item">\n        <span class="meta-label">Generated</span>\n        <span class="meta-value">{date_str}</span>\n      </div>\n    </div>\n  </header>\n  <div class="stats-grid">\n    <div class="stat-card">\n      <div class="stat-value">{policies_scanned}</div>\n      <div class="stat-label">Policies Scanned</div>\n    </div>\n    <div class="stat-card">\n      <div class="stat-value">{total_findings}</div>\n      <div class="stat-label">Findings (&ge; {args.severity_filter})</div>\n    </div>\n    <div class="stat-card">\n      <div class="stat-value val-critical">{critical_count}</div>\n      <div class="stat-label">Critical</div>\n    </div>\n    <div class="stat-card">\n      <div class="stat-value val-high">{high_count}</div>\n      <div class="stat-label">High</div>\n    </div>\n  </div>\n  <div class="sev-chart-section">\n    <div class="chart-wrapper">\n      <svg class="donut-chart" viewBox="0 0 42 42">\n        <circle class="donut-track" cx="21" cy="21" r="15.9155" fill="transparent" stroke-width="6"></circle>\n        {donut_segments}\n      </svg>\n      <div class="chart-center">\n        <span class="chart-total">{total_findings}</span>\n        <span class="chart-label">Findings</span>\n      </div>\n    </div>\n    <div class="legend-container">\n      <h2 class="sev-bar-title">Severity Breakdown</h2>\n      <div class="bar-legend">\n        {bar_legend}\n      </div>\n    </div>\n  </div>\n  <div class="chart-grid">\n    <div class="panel-section">\n      <h2 class="sev-bar-title">Findings by Domain</h2>\n      {domain_bars}\n    </div>\n    <div class="panel-section">\n      <h2 class="sev-bar-title">Findings by Resource</h2>\n      {resource_bars}\n    </div>\n  </div>\n  {history_html}\n  <section class="findings-section">\n    <h2 class="section-title">Findings &mdash; Severity &ge; {args.severity_filter}</h2>\n    {(finding_cards or empty_state)}\n  </section>\n  <footer class="report-footer">\n    <span>Cloud Audit Pipeline &mdash; Automated CSPM Report</span>\n    <span>{timestamp}</span>\n  </footer>\n</div>\n</body>\n</html>"""
    with open(report_path, "w") as file:
        file.write(html)


def generate_csv_report(findings: List[Dict[str, Any]], args: argparse.Namespace, report_path: str) -> None:
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    with open(report_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "CIS ID",
                "Severity",
                "Finding",
                "Affected Resource",
                "Environment",
                "Framework",
                "Timestamp",
            ],
        )
        for finding in findings:
            writer.writerow(
                [
                    finding["cis_id"],
                    finding["severity"],
                    finding["title"],
                    finding["resource"],
                    args.target_environment,
                    args.compliance_framework.upper(),
                    timestamp,
                ],
            )
