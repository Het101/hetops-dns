import re

with open('public/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Fonts and CSS vars
html = html.replace(
    '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">',
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet">'
)

css_vars = """    :root {
      --bg: #0a0c0f;
      --surface: #111318;
      --surface2: #181c22;
      --border: #1e2530;
      --accent: #00d4aa;
      --text: #e2e8f0;
      --text-muted: #64748b;
      --text-dim: #334155;"""
new_css_vars = """    :root {
      --bg: #020202;
      --surface: #0a0a0a;
      --surface2: #1a1a1a;
      --border: rgba(255, 255, 255, 0.08);
      --accent: #00ff41;
      --accent-sec: #0575e6;
      --text: #ffffff;
      --text-muted: #a0a0a0;
      --text-dim: #606060;"""
html = html.replace(css_vars, new_css_vars)

# 2. Add glass card and tabs CSS
css_add = """    * { margin: 0; padding: 0; box-sizing: border-box; }

    .glass-card {
      background: rgba(255, 255, 255, 0.03);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 24px;
      transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.05), 0 10px 30px -10px rgba(0, 0, 0, 0.5);
    }
    .gradient-text {
      background: linear-gradient(90deg, var(--accent) 0%, var(--accent-sec) 100%);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .nav-tabs {
      display: flex; gap: 1rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border); overflow-x: auto;
    }
    .nav-tab {
      padding: 0.75rem 1rem; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; transition: all 0.2s; white-space: nowrap;
    }
    .nav-tab:hover { color: var(--text); }
    .nav-tab.active { color: var(--accent); border-bottom-color: var(--accent); }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s; }
    @keyframes fadeIn { from { opacity:0; transform: translateY(5px); } to { opacity:1; transform:translateY(0); } }"""
html = html.replace("    * { margin: 0; padding: 0; box-sizing: border-box; }", css_add)

# 3. Typography switches
html = html.replace("font-family: 'JetBrains Mono', monospace;", "font-family: 'Plus Jakarta Sans', sans-serif;")
html = html.replace("font-family: 'Space Mono', monospace;", "font-family: 'Plus Jakarta Sans', sans-serif;")

# 4. Header and Tabs
header_old = """    <header class="header">
      <span class="logo-tag">HetOps.dev</span>
      <div class="header-title">
        <h1>DNS <span>Lookup</span></h1>
        <p>Batch lookup with resolver profiles, timing, and domain health checks</p>
      </div>
      <div class="header-badge">
        <span class="dot"></span>
        LIVE
      </div>
    </header>"""
header_new = """    <header class="header" style="border-bottom:none; margin-bottom:1rem;">
      <img src="/icon.svg" alt="HetOps Logo" style="height: 48px; width: auto; object-fit: contain;">
      <div class="header-title">
        <h1 class="gradient-text">NetTools</h1>
        <p>Premium all-in-one network utilities.</p>
      </div>
      <div class="header-badge">
        <span class="dot"></span> LIVE
      </div>
    </header>

    <div class="nav-tabs">
      <div class="nav-tab active" onclick="switchTab(event, 'dns')">DNS Lookup</div>
      <div class="nav-tab" onclick="switchTab(event, 'port')">Port Scan</div>
      <div class="nav-tab" onclick="switchTab(event, 'blacklist')">Blacklist</div>
      <div class="nav-tab" onclick="switchTab(event, 'geo')">GeoIP</div>
      <div class="nav-tab" onclick="switchTab(event, 'whois')">Whois</div>
    </div>

    <div id="tab-dns" class="tab-content active">"""
html = html.replace(header_old, header_new)

# Apply glass-card to search panel
html = html.replace('<div class="search-panel">', '<div class="search-panel glass-card" style="margin-bottom: 1.5rem;">')

# 5. Footer and Tab contents injection
footer_old = """    <footer class="footer">
      <span>DNS Lookup - HetOps.dev Tool</span>
      <span>Profiles: balanced, google, cloudflare, quad9, opendns, system</span>
    </footer>
  </div>"""

footer_new = """    </div> <!-- end tab-dns -->

    <!-- New Tabs -->
    <div id="tab-port" class="tab-content">
      <div class="search-panel glass-card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
        <div class="input-row">
          <div class="input-wrapper"><span class="input-prefix">$</span><textarea class="font-fira" id="portInput" placeholder="example.com" style="width:100%; min-height:45px; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:0.75rem 0.85rem 0.75rem 2.2rem; border-radius:6px; outline:none; resize:vertical; font-family:'Fira Code', monospace;"></textarea></div>
          <button class="btn-lookup" style="background:var(--accent); color:var(--bg); border:none; padding:0.75rem 1.5rem; border-radius:6px; font-weight:bold; cursor:pointer;" onclick="runPortScan()"><svg style="margin-right:8px; vertical-align:text-bottom;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21 21-4.35-4.35"/><circle cx="11" cy="11" r="8"/></svg> SCAN</button>
        </div>
        <p style="font-size:0.75rem; color:var(--text-muted); padding-left:10px;">Scans common critical ports.</p>
      </div>
      <div id="portResults" class="records-grid"></div>
    </div>

    <div id="tab-blacklist" class="tab-content">
      <div class="search-panel glass-card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
        <div class="input-row">
          <div class="input-wrapper"><span class="input-prefix">$</span><textarea class="font-fira" id="blacklistInput" placeholder="example.com" style="width:100%; min-height:45px; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:0.75rem 0.85rem 0.75rem 2.2rem; border-radius:6px; outline:none; resize:vertical; font-family:'Fira Code', monospace;"></textarea></div>
          <button class="btn-lookup" style="background:var(--accent); color:var(--bg); border:none; padding:0.75rem 1.5rem; border-radius:6px; font-weight:bold; cursor:pointer;" onclick="runBlacklist()"><svg style="margin-right:8px; vertical-align:text-bottom;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21 21-4.35-4.35"/><circle cx="11" cy="11" r="8"/></svg> CHECK</button>
        </div>
      </div>
      <div id="blacklistResults" class="records-grid"></div>
    </div>

    <div id="tab-geo" class="tab-content">
      <div class="search-panel glass-card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
        <div class="input-row">
          <div class="input-wrapper"><span class="input-prefix">$</span><textarea class="font-fira" id="geoInput" placeholder="example.com" style="width:100%; min-height:45px; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:0.75rem 0.85rem 0.75rem 2.2rem; border-radius:6px; outline:none; resize:vertical; font-family:'Fira Code', monospace;"></textarea></div>
          <button class="btn-lookup" style="background:var(--accent); color:var(--bg); border:none; padding:0.75rem 1.5rem; border-radius:6px; font-weight:bold; cursor:pointer;" onclick="runGeo()"><svg style="margin-right:8px; vertical-align:text-bottom;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21 21-4.35-4.35"/><circle cx="11" cy="11" r="8"/></svg> LOCATE</button>
        </div>
      </div>
      <div id="geoResults" clas
