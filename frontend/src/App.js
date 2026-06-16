import { useState, useRef, useEffect } from "react";

const API = "http://192.168.132.128:5000/api"
const C = {
  bg: "#080c14", surface: "#0d1421", card: "#111a2e",
  border: "#1a2d48", accent: "#00c8f0", green: "#00ff9d",
  yellow: "#ffd166", orange: "#ff9040", red: "#ff4060",
  text: "#dde8f5", muted: "#4a6a8a",
};

const SEV = {
  CRITICAL: { color: C.red,    bg: "rgba(255,64,96,0.12)",   border: "rgba(255,64,96,0.3)"   },
  HIGH:     { color: C.orange, bg: "rgba(255,144,64,0.12)",  border: "rgba(255,144,64,0.3)"  },
  MEDIUM:   { color: C.yellow, bg: "rgba(255,209,102,0.10)", border: "rgba(255,209,102,0.3)" },
  LOW:      { color: C.green,  bg: "rgba(0,255,157,0.08)",   border: "rgba(0,255,157,0.25)"  },
};

function riskColor(s) { return s>=86?C.red:s>=61?C.orange:s>=31?C.yellow:C.green; }
function riskLabel(s) { return s>=86?"CRITICAL":s>=61?"HIGH":s>=31?"MEDIUM":"LOW"; }

// ── PDF Generator ─────────────────────────────────────────────────────────────
async function loadScript(src) {
  if (document.querySelector(`script[src="${src}"]`)) return;
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src; s.onload = resolve; s.onerror = reject;
    document.head.appendChild(s);
  });
}

async function svgToPngDataUrl(svgElement) {
  return new Promise((resolve) => {
    try {
      const svgData = new XMLSerializer().serializeToString(svgElement);
      const svgBlob = new Blob([svgData], {type:"image/svg+xml;charset=utf-8"});
      const url     = URL.createObjectURL(svgBlob);
      const img     = new Image();
      img.onload = () => {
        const vb     = svgElement.viewBox?.baseVal;
        const srcW   = vb?.width  || 1000;
        const srcH   = vb?.height || 600;
        // رسم بدقة عالية (3x) عشان يطلع واضح في الـ PDF
        const scale  = 3;
        const canvas = document.createElement("canvas");
        canvas.width  = srcW * scale;
        canvas.height = srcH * scale;
        const ctx = canvas.getContext("2d");
        ctx.scale(scale, scale);
        ctx.fillStyle = "#080c14";
        ctx.fillRect(0, 0, srcW, srcH);
        ctx.drawImage(img, 0, 0, srcW, srcH);
        URL.revokeObjectURL(url);
        resolve(canvas.toDataURL("image/png", 1.0));
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
      img.src = url;
    } catch { resolve(null); }
  });
}

async function generatePDF(results) {
  await loadScript("https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js");

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation:"landscape", unit:"mm", format:"a4" });
  const W = 297, margin = 18;
  let y = margin;

  const rgb = {
    bg:      [8,12,20],  surface:[13,20,33],  card:[17,26,46],
    accent:  [0,200,240], text:[221,232,245],  muted:[74,106,138],
    red:     [255,64,96], orange:[255,144,64], yellow:[255,209,102],
    green:   [0,255,157],
  };
  const sevRgb = { CRITICAL:rgb.red, HIGH:rgb.orange, MEDIUM:rgb.yellow, LOW:rgb.green };

  // helpers
  const setPage = () => {
    doc.setFillColor(...rgb.bg);
    doc.rect(0, 0, W, 297, "F");
  };
  const newPage = () => { doc.addPage(); setPage(); y = margin; };
  const checkY  = (n=20) => { if (y+n > 280) newPage(); };

  const txt = (str, x, size=10, color=rgb.text, style="normal") => {
    doc.setFontSize(size); doc.setTextColor(...color);
    doc.setFont("helvetica", style); doc.text(str, x, y);
  };
  const hline = (color=rgb.muted) => {
    doc.setDrawColor(...color); doc.setLineWidth(0.3);
    doc.line(margin, y, W-margin, y); y+=5;
  };

  // ── Cover ─────────────────────────────────────────────────────────────────
  setPage();
  doc.setFillColor(...rgb.accent); doc.rect(0,0,W,2,"F");

  // SAGE title — مرة وحدة فقط
  y = 60;
  doc.setFontSize(42); doc.setFont("helvetica","bold"); doc.setTextColor(...rgb.accent);
  doc.text("SAGE", W/2, y, {align:"center"});

  y += 10;
  doc.setFontSize(13); doc.setTextColor(...rgb.muted); doc.setFont("helvetica","normal");
  doc.text("Non-IP IoT Vulnerability Scanner", W/2, y, {align:"center"});

  y += 14;
  doc.setFontSize(20); doc.setTextColor(...rgb.text); doc.setFont("helvetica","bold");
  doc.text("Security Assessment Report", W/2, y, {align:"center"});

  y += 8;
  doc.setFontSize(10); doc.setTextColor(...rgb.muted); doc.setFont("helvetica","normal");
  doc.text(`Generated: ${new Date().toLocaleString()}`, W/2, y, {align:"center"});

  // ── حساب الإحصائيات ────────────────────────────────────────────────────────
  y += 22;
  let totalVulns = 0;
  const bySev = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  results.forEach(fr => fr.results?.forEach(r =>
    r.vulns?.forEach(v => { totalVulns++; if(bySev[v.severity]!==undefined) bySev[v.severity]++; })
  ));

  const boxH = 42, boxGap = 8;
  const totalW = W - margin*2;
  // الصف الأول: مربعين — Files Scanned + Total Vulnerabilities
  const topBoxW = (totalW - boxGap) / 2;

  // مربع Files Scanned
  doc.setFillColor(...rgb.surface);
  doc.roundedRect(margin, y, topBoxW, boxH, 3, 3, "F");
  doc.setDrawColor(...rgb.accent); doc.setLineWidth(0.4);
  doc.roundedRect(margin, y, topBoxW, boxH, 3, 3, "S");
  doc.setFontSize(9); doc.setTextColor(...rgb.muted); doc.setFont("helvetica","normal");
  doc.text("FILES SCANNED", margin+6, y+8);
  doc.setFontSize(20); doc.setFont("helvetica","bold"); doc.setTextColor(...rgb.accent);
  doc.text(`${results.length}`, margin+6, y+24);

  // مربع Total Vulnerabilities
  const box2x = margin + topBoxW + boxGap;
  doc.setFillColor(...rgb.surface);
  doc.roundedRect(box2x, y, topBoxW, boxH, 3, 3, "F");
  doc.setDrawColor(...(totalVulns>0?rgb.red:rgb.green)); doc.setLineWidth(0.4);
  doc.roundedRect(box2x, y, topBoxW, boxH, 3, 3, "S");
  doc.setFontSize(9); doc.setTextColor(...rgb.muted); doc.setFont("helvetica","normal");
  doc.text("TOTAL VULNERABILITIES", box2x+6, y+8);
  doc.setFontSize(26); doc.setFont("helvetica","bold");
  doc.setTextColor(...(totalVulns>0?rgb.red:rgb.green));
  doc.text(`${totalVulns}`, box2x+6, y+24);

  // الصف الثاني: مربع واحد يحتوي الـ severity breakdown
  y += boxH + boxGap;
  const sevBoxH = 46;
  doc.setFillColor(...rgb.surface);
  doc.roundedRect(margin, y, totalW, sevBoxH, 3, 3, "F");
  doc.setDrawColor(...rgb.muted); doc.setLineWidth(0.3);
  doc.roundedRect(margin, y, totalW, sevBoxH, 3, 3, "S");

  doc.setFontSize(9); doc.setTextColor(...rgb.muted); doc.setFont("helvetica","normal");
  doc.text("SEVERITY BREAKDOWN", margin+6, y+8);

  // كل severity في عمود
  const sevList = Object.entries(bySev);
  const colW = totalW / sevList.length;
  sevList.forEach(([sev, cnt], i) => {
    const cx = margin + i * colW + colW/2;
    // خط فاصل بين الأعمدة
    if (i > 0) {
      doc.setDrawColor(...rgb.card); doc.setLineWidth(0.5);
      doc.line(margin + i*colW, y+10, margin + i*colW, y+sevBoxH-4);
    }
    // الرقم
    doc.setFontSize(20); doc.setFont("helvetica","bold");
    doc.setTextColor(...(sevRgb[sev]||rgb.muted));
    doc.text(`${cnt}`, cx, y+24, {align:"center"});
    // الاسم
    doc.setFontSize(8); doc.setFont("helvetica","normal");
    doc.setTextColor(...(sevRgb[sev]||rgb.muted));
    doc.text(sev, cx, y+31, {align:"center"});
  });

  // ── Per-file ───────────────────────────────────────────────────────────────
  results.forEach(fileResult => {
    newPage();

    // File bar
    doc.setFillColor(...rgb.surface);
    doc.rect(0, y-5, W, 14, "F");
    doc.setFontSize(13); doc.setFont("helvetica","bold"); doc.setTextColor(...rgb.accent);
    doc.text(`${fileResult.file}`, margin, y+2);
    doc.setFontSize(9); doc.setFont("helvetica","normal"); doc.setTextColor(...rgb.muted);
    doc.text(`Scan time: ${fileResult.scan_time}s  |  ${new Date().toLocaleDateString()}`,
      W-margin, y+2, {align:"right"});
    y += 14;
    hline(rgb.accent);

    fileResult.results?.forEach(proto => {
      if (!proto.vulns?.length) return;
      checkY(24);

      const pc = proto.protocol==="Zigbee"?rgb.yellow:
                 proto.protocol==="BLE"?rgb.accent:rgb.green;

      // Protocol header
      doc.setFillColor(...rgb.card);
      doc.rect(margin, y-3, W-margin*2, 13, "F");
      doc.setFillColor(...pc); doc.rect(margin, y-3, 3, 13, "F");

      doc.setFontSize(13); doc.setFont("helvetica","bold"); doc.setTextColor(...pc);
      doc.text(proto.protocol, margin+7, y+5);

      if (proto.risk_score !== undefined) {
        const rl = riskLabel(proto.risk_score);
        doc.setFontSize(10); doc.setFont("helvetica","normal");
        doc.setTextColor(...(sevRgb[rl]||rgb.muted));
        doc.text(`Risk: ${proto.risk_score}/100 (${rl})`, W-margin-45, y+5);
      }
      y += 16;

      // Each vuln
      proto.vulns.forEach((vuln, vi) => {
        const linesNeeded = 14 +
          (vuln.evidence    ? 8  : 0) +
          (vuln.remediation ? 8  : 0);
        checkY(linesNeeded);

        const sc = sevRgb[vuln.severity] || rgb.muted;

        // Card bg + left border
        doc.setFillColor(...rgb.surface);
        doc.rect(margin, y-2, W-margin*2, linesNeeded, "F");
        doc.setFillColor(...sc);
        doc.rect(margin, y-2, 2.5, linesNeeded, "F");

        // Row 1: index + severity + id + cve
        doc.setFontSize(10); doc.setFont("helvetica","bold"); doc.setTextColor(...sc);
        doc.text(`[${vi+1}] ${vuln.severity}`, margin+6, y+4);

        doc.setFontSize(9); doc.setFont("helvetica","normal"); doc.setTextColor(...rgb.muted);
        doc.text(vuln.id||"", margin+36, y+4);

        if (vuln.cve?.length) {
          const cveStr = Array.isArray(vuln.cve)?vuln.cve.join(", "):vuln.cve;
          doc.setTextColor(...rgb.accent);
          doc.text(cveStr, W-margin-4, y+4, {align:"right"});
        }

        // Row 2: title
        y += 8;
        doc.setFontSize(11); doc.setFont("helvetica","bold"); doc.setTextColor(...rgb.text);
        const titleLines = doc.splitTextToSize(vuln.title||"", W-margin*2-12);
        doc.text(titleLines, margin+6, y);
        y += titleLines.length * 4 + 2;

        // Evidence
        if (vuln.evidence) {
          doc.setFontSize(9); doc.setFont("helvetica","normal");
          doc.setTextColor(...rgb.muted); doc.text("Evidence:", margin+6, y);
          doc.setTextColor(...rgb.text);
          const evLines = doc.splitTextToSize(vuln.evidence, W-margin*2-32);
          doc.text(evLines, margin+26, y);
          y += Math.max(evLines.length*4, 5);
        }

        // Remediation
        if (vuln.remediation) {
          doc.setFontSize(9); doc.setFont("helvetica","normal");
          doc.setTextColor(0,180,110); doc.text("Fix:", margin+6, y);
          doc.setTextColor(...rgb.text);
          const remLines = doc.splitTextToSize(vuln.remediation, W-margin*2-22);
          doc.text(remLines, margin+18, y);
          y += Math.max(remLines.length*4, 5);
        }

        y += 7;
      });
      y += 6;
    });
  });

  // ── Topology Pages ─────────────────────────────────────────────────────────
  const svgElements = document.querySelectorAll("svg[data-topo]");

  if (svgElements.length > 0) {
    for (const svg of svgElements) {

      // ── صفحة 1: Graph (landscape كاملة) ──────────────────────────────────
      newPage();
      const PW = 297, PH = 210;
      doc.setFillColor(...rgb.bg);
      doc.rect(0, 0, PW, PH, "F");

      // Header
      doc.setFillColor(...rgb.surface);
      doc.rect(0, 0, PW, 16, "F");
      doc.setFillColor(...rgb.accent);
      doc.rect(0, 0, PW, 2, "F");
      doc.setFontSize(11); doc.setFont("helvetica","bold");
      doc.setTextColor(...rgb.accent);
      doc.text("NETWORK TOPOLOGY", margin, y+2);
      y += 14; hline(rgb.accent);
      const fileLabel = svg.getAttribute("data-topo") || "";
      if (fileLabel) {
        doc.setFontSize(9); doc.setFont("helvetica","normal");
        doc.setTextColor(...rgb.muted);
        doc.text(fileLabel, W-margin, y-8, {align:"right"});
      }

      // Graph — full page
      const pngUrl = await svgToPngDataUrl(svg);
      if (pngUrl) {
        const imgW = W - margin * 2;
        const imgH = 175;
        doc.addImage(pngUrl, "PNG", margin, y, imgW, imgH);
      } else {
        doc.setFontSize(9); doc.setTextColor(...rgb.muted);
        doc.text("Topology graph unavailable — open Topology tab first", margin, 50);
      }

      // ── صفحة 2: Device Table ───────────────────────────────────────────────
      const protoColors2 = { Zigbee: rgb.yellow, BLE: rgb.accent, "Z-Wave": rgb.green };
      const allNodesForPdf = [];
      results.forEach(fr => {
        fr.results?.forEach(r => {
          r.topology?.nodes?.forEach(n => {
            allNodesForPdf.push({
              protocol:    r.protocol,
              id:          n.id || "",
              device_type: n.device_type || "Device",
              role:        (n.role || "").toUpperCase(),
              packets:     n.packet_count || 0,
              encrypted:   n.encrypted || 0,
              unencrypted: n.unencrypted || 0,
              secure:      (n.encrypted||0) > 0 && (n.unencrypted||0) === 0,
              exposed:     (n.unencrypted||0) > 0,
            });
          });
        });
      });

      if (allNodesForPdf.length > 0) {
        newPage();
        doc.setFillColor(...rgb.surface);
        doc.rect(0, y-5, W, 14, "F");
        doc.setFontSize(11); doc.setFont("helvetica","bold");
        doc.setTextColor(...rgb.accent);
        doc.text("DISCOVERED DEVICES", margin, y+2);
        doc.setFontSize(8); doc.setFont("helvetica","normal");
        doc.setTextColor(...rgb.muted);
        doc.text(`${allNodesForPdf.length} device${allNodesForPdf.length!==1?"s":""}`, W-margin, y+2, {align:"right"});
        y += 14;
        hline(rgb.accent);

        // Columns — fit within W=210, margin=18 → usable = 174mm
        const cols = [
          {label:"Protocol",    x: margin,      w: 32},
          {label:"Node ID",     x: margin+32,   w: 55},
          {label:"Device Type", x: margin+87,   w: 55},
          {label:"Role",        x: margin+142,  w: 35},
          {label:"Pkts",        x: margin+177,  w: 20},
          {label:"Enc",         x: margin+197,  w: 20},
          {label:"Unenc",       x: margin+217,  w: 22},
          {label:"Status",      x: margin+239,  w: 35},
        ];

        // Header row
        doc.setFillColor(...rgb.card);
        doc.rect(margin, y-3, W-margin*2, 8, "F");
        doc.setFontSize(9); doc.setFont("helvetica","bold");
        doc.setTextColor(...rgb.muted);
        cols.forEach(c => doc.text(c.label, c.x, y));
        y += 3;
        doc.setDrawColor(...rgb.accent); doc.setLineWidth(0.3);
        doc.line(margin, y, W-margin, y);
        y += 5;

        // Data rows
        doc.setFont("helvetica","normal");
        allNodesForPdf.forEach((n, i) => {
          checkY(8);

          // Alternating bg
          if (i % 2 === 0) {
            doc.setFillColor(...rgb.surface);
            doc.rect(margin, y-3, W-margin*2, 7, "F");
          }

          // Protocol color bar
          const pc = protoColors2[n.protocol] || rgb.muted;
          doc.setFillColor(...pc);
          doc.rect(margin, y-3, 1.5, 7, "F");

          doc.setFontSize(9);

          doc.setTextColor(...pc);
          doc.text(n.protocol, cols[0].x+2, y);

          doc.setTextColor(...rgb.text);
          doc.text(n.id.slice(0,18), cols[1].x, y);
          doc.text(n.device_type.slice(0,18), cols[2].x, y);

          const isCtrl = ["COORDINATOR","CONTROLLER","CENTRAL"].includes(n.role);
          doc.setTextColor(isCtrl?pc[0]:rgb.muted[0], isCtrl?pc[1]:rgb.muted[1], isCtrl?pc[2]:rgb.muted[2]);
          doc.setFont("helvetica", isCtrl?"bold":"normal");
          doc.text(n.role.slice(0,10), cols[3].x, y);

          doc.setFont("helvetica","normal");
          doc.setTextColor(...rgb.text);
          doc.text(String(n.packets), cols[4].x, y);

          doc.setTextColor(...rgb.green);
          doc.text(String(n.encrypted), cols[5].x, y);

          doc.setTextColor(...(n.unencrypted>0?rgb.red:rgb.muted));
          doc.text(String(n.unencrypted), cols[6].x, y);

          const sc = n.secure?rgb.green:n.exposed?rgb.red:rgb.yellow;
          doc.setTextColor(...sc);
          doc.setFont("helvetica","bold");
          doc.text(n.secure?"Secure":n.exposed?"Exposed":"Mixed", cols[7].x, y);

          y += 9;
        });
      }
    }
  }

  // ── Footer ─────────────────────────────────────────────────────────────────
  const pages = doc.getNumberOfPages();
  for (let i=1; i<=pages; i++) {
    doc.setPage(i);
    // landscape: H=210, portrait: H=297 — نكتشف من عدد الصفحات
    const pageH = doc.internal.pageSize.getHeight();
    const footerY = pageH - 8;
    doc.setFillColor(...rgb.surface); doc.rect(0, footerY-4, W, 12, "F");
    doc.setFontSize(9); doc.setFont("helvetica","normal"); doc.setTextColor(...rgb.muted);
    doc.text("SAGE — Non-IP IoT Vulnerability Scanner", margin, footerY+2);
    doc.text(`Page ${i} of ${pages}`, W-margin, footerY+2, {align:"right"});
  }

  doc.save(`SAGE_Report_${new Date().toISOString().slice(0,10)}.pdf`);
}

// ── Gauge ─────────────────────────────────────────────────────────────────────
function Gauge({ score }) {
  const c = riskColor(score);
  const r = 42, circ = 2*Math.PI*r;
  const dash = (score/100)*circ*0.75;
  return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
      <svg width={110} height={85} viewBox="0 0 110 85">
        <circle cx={55} cy={68} r={r} fill="none" stroke={C.border} strokeWidth={8}
          strokeDasharray={`${circ*0.75} ${circ}`} strokeDashoffset={circ*0.125} strokeLinecap="round"/>
        <circle cx={55} cy={68} r={r} fill="none" stroke={c} strokeWidth={8}
          strokeDasharray={`${dash} ${circ-dash}`} strokeDashoffset={circ*0.125} strokeLinecap="round"
          style={{filter:`drop-shadow(0 0 6px ${c})`,transition:"stroke-dasharray .6s ease"}}/>
        <text x={55} y={62} textAnchor="middle" fill={c} fontSize={22} fontWeight={700}
          fontFamily="'IBM Plex Mono',monospace">{score}</text>
        <text x={55} y={74} textAnchor="middle" fill={C.muted} fontSize={9} fontFamily="monospace">/100</text>
      </svg>
      <span style={{fontSize:10,fontWeight:700,letterSpacing:2,color:c,
        background:SEV[riskLabel(score)]?.bg||"transparent",
        padding:"2px 10px",borderRadius:20,
        border:`1px solid ${SEV[riskLabel(score)]?.border||"transparent"}`}}>
        {riskLabel(score)}
      </span>
    </div>
  );
}

// ── CVE Lookup ────────────────────────────────────────────────────────────────
function CVEBadge({ cveId }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [open,    setOpen]    = useState(false);

  const lookup = async (e) => {
    e.stopPropagation();
    if (data) { setOpen(!open); return; }
    setLoading(true);
    try {
      const res = await fetch(`${API}/cve/${cveId}`);
      const json = await res.json();
      setData(json);
      setOpen(true);
    } catch {
      setData({ error: "Failed to fetch" });
    }
    setLoading(false);
  };

  const scoreColor = data?.score >= 9 ? C.red
    : data?.score >= 7 ? C.orange
    : data?.score >= 4 ? C.yellow : C.green;

  return (
    <div style={{display:"inline-block"}}>
      <span onClick={lookup} style={{
        fontFamily:"'IBM Plex Mono',monospace", fontSize:10, color:C.accent,
        background:`${C.accent}15`, border:`1px solid ${C.accent}40`,
        borderRadius:4, padding:"2px 7px", cursor:"pointer",
        display:"inline-flex", alignItems:"center", gap:5,
        transition:"all .2s"}}>
        {loading ? "…" : cveId}
        {data && !data.error && (
          <span style={{color:scoreColor, fontWeight:700}}>
            {data.score}
          </span>
        )}
      </span>
      {open && data && !data.error && (
        <div onClick={e=>e.stopPropagation()} style={{
          marginTop:8, background:C.bg, border:`1px solid ${C.accent}40`,
          borderRadius:8, padding:"10px 14px", fontSize:11,
          display:"flex", flexDirection:"column", gap:6}}>
          <div style={{display:"flex", alignItems:"center", gap:8, marginBottom:2}}>
            <span style={{fontWeight:700, color:C.accent, fontFamily:"monospace"}}>{data.id}</span>
            {data.score && (
              <span style={{
                fontSize:9, fontWeight:700, color:scoreColor,
                background:`${scoreColor}20`, border:`1px solid ${scoreColor}50`,
                borderRadius:10, padding:"1px 8px"}}>
                CVSS {data.score} — {data.severity}
              </span>
            )}
            {data.published && (
              <span style={{fontSize:9, color:C.muted}}>{data.published}</span>
            )}
          </div>
          <div style={{color:C.text, lineHeight:1.6, fontSize:11}}>
            {data.description?.slice(0, 300)}{data.description?.length > 300 ? "…" : ""}
          </div>
          {data.vector && (
            <div style={{fontFamily:"monospace", fontSize:9, color:C.muted,
              background:C.card, borderRadius:4, padding:"4px 8px"}}>
              {data.vector}
            </div>
          )}
          {data.references?.length > 0 && (
            <div style={{display:"flex", gap:6, flexWrap:"wrap"}}>
              {data.references.map((r,i) => (
                <a key={i} href={r} target="_blank" rel="noreferrer"
                  onClick={e=>e.stopPropagation()}
                  style={{fontSize:9, color:C.accent, textDecoration:"none"}}>
                  🔗 Reference {i+1}
                </a>
              ))}
            </div>
          )}
          <button onClick={e=>{e.stopPropagation();setOpen(false)}}
            style={{alignSelf:"flex-end", background:"none", border:"none",
              color:C.muted, cursor:"pointer", fontSize:10}}>
            close ✕
          </button>
        </div>
      )}
      {open && data?.error && (
        <div style={{marginTop:4, fontSize:9, color:C.red}}>{data.error}</div>
      )}
    </div>
  );
}

// ── VulnCard ──────────────────────────────────────────────────────────────────
function VulnCard({ v }) {
  const [open,    setOpen]    = useState(false);
  const [showFix, setShowFix] = useState(false);
  const s = SEV[v.severity]||{color:C.muted,bg:"transparent",border:C.border};
  return (
    <div onClick={()=>setOpen(!open)} style={{
      background:open?s.bg:C.card, border:`1px solid ${open?s.border:C.border}`,
      borderLeft:`3px solid ${s.color}`, borderRadius:8, padding:"11px 15px",
      cursor:"pointer", transition:"all .2s", marginBottom:6,
      boxShadow:open?`0 0 12px ${s.color}18`:"none"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontSize:9,fontWeight:700,letterSpacing:1.5,color:s.color,
            background:s.bg,border:`1px solid ${s.border}`,padding:"2px 7px",borderRadius:4}}>
            {v.severity}
          </span>
          <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:10,color:C.muted}}>
            {v.id}
          </span>
        </div>
        <span style={{color:C.muted,fontSize:12,display:"inline-block",
          transform:open?"rotate(90deg)":"rotate(0)",transition:"transform .2s"}}>›</span>
      </div>
      <div style={{marginTop:5,fontSize:13,fontWeight:600,color:C.text}}>{v.title}</div>
      {open && (
        <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:6,
          borderTop:`1px solid ${C.border}`,paddingTop:10}}>
          {v.description   && <Row label="Description"   val={v.description}/>}
          {v.evidence      && <Row label="Evidence"      val={v.evidence} mono/>}
          {v.cve?.length>0 && (
            <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
              <span style={{fontSize:10,color:C.muted,minWidth:90,flexShrink:0}}>CVE</span>
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                {v.cve.map(c=><CVEBadge key={c} cveId={c}/>)}
              </div>
            </div>
          )}
          {v.attack_vector && <Row label="Attack Vector" val={v.attack_vector}/>}
          {v.remediation   && <Row label="Fix"           val={v.remediation} green/>}

          {/* Fix Code Button */}
          {v.fix_code && (
            <div onClick={e=>e.stopPropagation()}>
              <button onClick={()=>setShowFix(!showFix)} style={{
                display:"flex",alignItems:"center",gap:6,
                background:showFix?`${C.green}20`:`${C.accent}10`,
                border:`1px solid ${showFix?C.green:C.accent}50`,
                borderRadius:6,padding:"5px 12px",cursor:"pointer",
                color:showFix?C.green:C.accent,fontSize:10,fontWeight:700,
                fontFamily:"'Syne',sans-serif",marginTop:4,transition:"all .2s"}}>
                <span>{showFix?"▾":"▸"}</span>
                {showFix?"Hide Fix Code":"Show Fix Code"}
              </button>
              {showFix && (
                <div style={{marginTop:8,position:"relative"}}>
                  <pre style={{
                    background:C.bg,border:`1px solid ${C.green}40`,
                    borderRadius:8,padding:"12px 14px",
                    fontFamily:"'IBM Plex Mono',monospace",fontSize:10,
                    color:C.text,lineHeight:1.6,overflowX:"auto",
                    maxHeight:300,overflowY:"auto",margin:0,
                    borderLeft:`3px solid ${C.green}`}}>
                    {v.fix_code.trim()}
                  </pre>
                  <button onClick={()=>navigator.clipboard.writeText(v.fix_code.trim())}
                    style={{position:"absolute",top:8,right:8,
                      background:C.card,border:`1px solid ${C.border}`,
                      borderRadius:4,padding:"3px 8px",cursor:"pointer",
                      color:C.muted,fontSize:9,fontFamily:"'Syne',sans-serif"}}>
                    Copy
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, val, mono, accent, green }) {
  const color = accent?C.accent:green?C.green:C.text;
  return (
    <div style={{display:"flex",gap:10}}>
      <span style={{fontSize:10,color:C.muted,minWidth:90,paddingTop:1,flexShrink:0}}>{label}</span>
      <span style={{fontSize:12,color,lineHeight:1.5,
        fontFamily:mono||accent?"'IBM Plex Mono',monospace":"inherit"}}>{val}</span>
    </div>
  );
}

// ── ProtocolResult ────────────────────────────────────────────────────────────
function ProtocolResult({ r }) {
  const {protocol,vulns=[],risk_score,statistics,error} = r;
  const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  vulns.forEach(v=>{if(counts[v.severity]!==undefined)counts[v.severity]++;});
  const pc = protocol==="Zigbee"?C.yellow:protocol==="BLE"?C.accent:C.green;
  return (
    <div style={{background:C.surface,border:`1px solid ${C.border}`,
      borderRadius:12,overflow:"hidden",marginBottom:14}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
        padding:"12px 18px",borderBottom:`1px solid ${C.border}`,background:C.card}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:8,height:8,borderRadius:"50%",background:pc,boxShadow:`0 0 8px ${pc}`}}/>
          <span style={{fontWeight:700,fontSize:15,color:C.text}}>{protocol}</span>
        </div>
        {!error && typeof risk_score==="number" && <Gauge score={risk_score}/>}
      </div>
      <div style={{padding:"14px 18px"}}>
        {error ? (
          <div style={{color:C.red,fontFamily:"monospace",fontSize:12}}>⚠ {error}</div>
        ) : (
          <>
            {statistics && Object.keys(statistics).length > 0 && (
              <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:14}}>
                {Object.entries(statistics).map(([k,v])=>(
                  <div key={k} style={{flex:1,minWidth:80,background:C.bg,
                    border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px"}}>
                    <div style={{fontSize:18,fontWeight:700,color:C.accent,
                      fontFamily:"'IBM Plex Mono',monospace"}}>{v}</div>
                    <div style={{fontSize:9,color:C.muted,letterSpacing:1,
                      textTransform:"uppercase",marginTop:2}}>{k.replace(/_/g," ")}</div>
                  </div>
                ))}
              </div>
            )}
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
              {Object.entries(counts).map(([sev,cnt])=>(
                <div key={sev} style={{display:"flex",alignItems:"center",gap:5,
                  background:SEV[sev]?.bg,border:`1px solid ${SEV[sev]?.border}`,
                  borderRadius:20,padding:"3px 11px",fontSize:10,fontWeight:700,
                  color:SEV[sev]?.color,letterSpacing:1}}>
                  <span>{cnt}</span><span>{sev}</span>
                </div>
              ))}
            </div>
            {vulns.length===0
              ? <div style={{color:C.green,fontSize:12}}>✓ No vulnerabilities detected</div>
              : vulns.map((v,i)=><VulnCard key={v.id+i} v={v}/>)
            }
          </>
        )}
      </div>
    </div>
  );
}

function Dots() {
  return (
    <div style={{display:"flex",gap:5,alignItems:"center"}}>
      {[0,1,2].map(i=>(
        <div key={i} style={{width:6,height:6,borderRadius:"50%",background:C.accent,
          animation:`pulse 1.1s ease-in-out ${i*0.18}s infinite`}}/>
      ))}
    </div>
  );
}

// ── Topology Page ─────────────────────────────────────────────────────────────
function TopologyPage({ results }) {
  const protoColors = { Zigbee:C.yellow, BLE:C.accent, "Z-Wave":C.green };

  return (
    <div style={{animation:"fadeUp .3s ease"}}>
      <div style={{marginBottom:20}}>
        <div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:11,
          color:C.accent,letterSpacing:2,marginBottom:4}}>NETWORK TOPOLOGY</div>
        <div style={{fontSize:12,color:C.muted}}>
          Real device map extracted from captured packets
        </div>
      </div>

      {results.map((fr, fi) => {
        // اجمع كل الـ nodes والـ edges من كل البروتوكولات
        const allNodes = [];
        const allEdges = [];
        const protoList = [];

        fr.results?.forEach(r => {
          if (!r.topology) return;
          const color = protoColors[r.protocol] || C.muted;
          protoList.push({ protocol: r.protocol, color,
            nodeCount: r.topology.nodes?.length || 0,
            vulnCount: r.vulns?.length || 0,
          });
          r.topology.nodes?.forEach(n => allNodes.push({ ...n, color }));
          r.topology.edges?.forEach(e => allEdges.push({ ...e, color,
            protocol: r.protocol }));
        });

        const hasData = allNodes.length > 0;

        return (
          <div key={fi} style={{marginBottom:32}}>
            {/* File header */}
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:16}}>
              <div style={{height:1,flex:1,background:C.border}}/>
              <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:10,
                color:C.accent,letterSpacing:1}}>📄 {fr.file}</span>
              <div style={{height:1,flex:1,background:C.border}}/>
            </div>

            {/* Protocol summary badges */}
            <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
              {protoList.map(p=>(
                <div key={p.protocol} style={{display:"flex",alignItems:"center",gap:8,
                  padding:"6px 14px",borderRadius:20,
                  background:`${p.color}15`,border:`1px solid ${p.color}50`}}>
                  <div style={{width:7,height:7,borderRadius:"50%",
                    background:p.color,boxShadow:`0 0 6px ${p.color}`}}/>
                  <span style={{fontSize:11,fontWeight:700,color:p.color}}>
                    {p.protocol}
                  </span>
                  <span style={{fontSize:10,color:C.muted}}>
                    {p.nodeCount} node{p.nodeCount!==1?"s":""}
                  </span>
                  {p.vulnCount>0 && (
                    <span style={{fontSize:10,color:C.red}}>⚠ {p.vulnCount}</span>
                  )}
                </div>
              ))}
            </div>

            {!hasData ? (
              <div style={{background:C.surface,border:`1px solid ${C.border}`,
                borderRadius:12,padding:40,textAlign:"center",color:C.muted,fontSize:12}}>
                No topology data — make sure plugins are patched with patch_topology.py
              </div>
            ) : (
              <>
                {/* Unified Graph */}
                <div style={{background:C.surface,border:`1px solid ${C.border}`,
                  borderRadius:12,padding:20,marginBottom:14}}>
                  <RealTopoGraph nodes={allNodes} edges={allEdges}
                    protoColors={protoColors} topoLabel={fr.file}/>
                </div>

                {/* Device table */}
                <div style={{background:C.surface,border:`1px solid ${C.border}`,
                  borderRadius:12,overflow:"hidden"}}>
                  <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,
                    fontSize:9,color:C.muted,letterSpacing:2}}>
                    DISCOVERED DEVICES ({allNodes.length})
                  </div>
                  <div style={{overflowX:"auto"}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                      <thead>
                        <tr style={{borderBottom:`1px solid ${C.border}`}}>
                          {["Protocol","Node ID","Device Type","Role","Packets","Encrypted","Unencrypted","Status"]
                            .map(h=>(
                            <th key={h} style={{padding:"8px 14px",textAlign:"left",
                              color:C.muted,fontSize:9,letterSpacing:1,fontWeight:600}}>
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {allNodes.map((n,i)=>{
                          const secure = (n.encrypted||0) > 0 && (n.unencrypted||0) === 0;
                          const isCtrl = n.role==="coordinator"||n.role==="controller"||n.role==="central";
                          return (
                            <tr key={i} style={{borderBottom:`1px solid ${C.border}22`,
                              background:i%2===0?"transparent":C.card+"44"}}>
                              <td style={{padding:"8px 14px"}}>
                                <div style={{display:"flex",alignItems:"center",gap:6}}>
                                  <div style={{width:6,height:6,borderRadius:"50%",
                                    background:n.color,boxShadow:`0 0 4px ${n.color}`}}/>
                                  <span style={{color:n.color,fontWeight:600,fontSize:10}}>
                                    {n.protocol}
                                  </span>
                                </div>
                              </td>
                              <td style={{padding:"8px 14px",fontFamily:"monospace",
                                color:C.text,fontSize:11}}>{n.id}</td>
                              <td style={{padding:"8px 14px",color:C.text,fontWeight:600}}>
                                {n.device_type || "—"}
                              </td>
                              <td style={{padding:"8px 14px"}}>
                                <span style={{
                                  fontSize:9,fontWeight:700,letterSpacing:1,
                                  color:isCtrl?n.color:C.muted,
                                  background:isCtrl?`${n.color}15`:"transparent",
                                  padding:"2px 8px",borderRadius:10,
                                  border:`1px solid ${isCtrl?n.color+"40":"transparent"}`
                                }}>
                                  {n.role?.toUpperCase()}
                                </span>
                              </td>
                              <td style={{padding:"8px 14px",color:C.text}}>
                                {n.packet_count||0}
                              </td>
                              <td style={{padding:"8px 14px",color:C.green}}>
                                {n.encrypted||0}
                              </td>
                              <td style={{padding:"8px 14px",
                                color:(n.unencrypted||0)>0?C.red:C.muted}}>
                                {n.unencrypted||0}
                              </td>
                              <td style={{padding:"8px 14px"}}>
                                <span style={{fontSize:10,fontWeight:700,
                                  color:secure?C.green:(n.unencrypted||0)>0?C.red:C.yellow}}>
                                  {secure?"🔒 Secure":(n.unencrypted||0)>0?"🔓 Exposed":"⚠ Mixed"}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

function RealTopoGraph({ nodes, edges, protoColors, topoLabel }) {
  const W = 1000, H = 600;
  if (!nodes.length) return null;

  // Layout — force-directed بشكل بسيط
  // نجمع الـ nodes حسب البروتوكول، كل بروتوكول في دائرة
  const byProto = {};
  nodes.forEach(n => {
    if (!byProto[n.protocol]) byProto[n.protocol] = [];
    byProto[n.protocol].push(n);
  });

  const protos = Object.keys(byProto);
  const positioned = {};

  protos.forEach((proto, pi) => {
    const groupNodes = byProto[proto];
    const sectionW   = W / protos.length;
    const groupCx    = sectionW * pi + sectionW / 2;
    const groupCy    = H / 2;
    const r          = Math.min(200, sectionW * 0.45);

    groupNodes.forEach((node, ni) => {
      let x, y;
      // Controller/coordinator في المنتصف
      if (node.role === "coordinator" || node.role === "controller" ||
          node.role === "central") {
        x = groupCx;
        y = groupCy;
      } else {
        const devices = groupNodes.filter(n =>
          n.role !== "coordinator" && n.role !== "controller" && n.role !== "central"
        );
        const di    = devices.indexOf(node);
        const total = devices.length || 1;
        const angle = (2 * Math.PI / total) * di - Math.PI / 2;
        x = groupCx + Math.cos(angle) * r;
        y = groupCy + Math.sin(angle) * r;
      }
      positioned[node.id] = { ...node, x, y };
    });
  });

  return (
    <svg viewBox={`0 0 ${W} ${H}`} data-topo={topoLabel||"topology"}
      style={{width:"100%",height:560,background:C.card,borderRadius:8}}>

      {/* Grid dots */}
      {Array.from({length:19},(_,i)=>Array.from({length:11},(_,j)=>(
        <circle key={`g${i}${j}`} cx={i*50} cy={j*50} r={1}
          fill={C.border} opacity={0.3}/>
      )))}

      {/* Section dividers */}
      {Array.from({length:protos.length-1},(_,i)=>(
        <line key={`d${i}`}
          x1={W/protos.length*(i+1)} y1={30}
          x2={W/protos.length*(i+1)} y2={H-30}
          stroke={C.border} strokeWidth={1}
          strokeDasharray="4,6" opacity={0.6}/>
      ))}

      {/* Protocol labels top */}
      {protos.map((proto, pi) => {
        const sectionW = W / protos.length;
        const cx = sectionW * pi + sectionW / 2;
        const color = protoColors[proto] || C.muted;
        return (
          <g key={proto}>
            <rect x={cx-35} y={12} width={70} height={16} rx={8}
              fill={`${color}20`} stroke={`${color}60`} strokeWidth={1}/>
            <text x={cx} y={22} textAnchor="middle"
              fill={color} fontSize={9} fontWeight={700} letterSpacing={1}>
              {proto.toUpperCase()}
            </text>
          </g>
        );
      })}

      {/* Edges */}
      {edges.map((e, i) => {
        const from = positioned[e.from];
        const to   = positioned[e.to];
        if (!from || !to) return null;
        const secure = e.secure !== false;
        const mx = (from.x + to.x) / 2;
        const my = (from.y + to.y) / 2;
        return (
          <g key={i}>
            <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={secure ? e.color : C.red}
              strokeWidth={1.5 + Math.min(e.count/20, 2)}
              strokeDasharray={secure ? "" : "6,4"}
              opacity={0.5}/>
            {/* Mid badge */}
            <circle cx={mx} cy={my} r={6}
              fill={C.card} stroke={secure?e.color:C.red} strokeWidth={1}/>
            <text x={mx} y={my} textAnchor="middle"
              dominantBaseline="middle" fontSize={7}
              fill={secure?e.color:C.red}>
              {secure ? "🔒" : "!"}
            </text>
          </g>
        );
      })}

      {/* Device nodes */}
      {Object.values(positioned).filter(n =>
        n.role !== "coordinator" && n.role !== "controller" && n.role !== "central"
      ).map(n => {
        const label = n.device_type || n.label || n.id;
        const shortLabel = label.length > 12 ? label.slice(0,11)+"…" : label;
        return (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={20}
              fill={C.surface}
              stroke={(n.unencrypted||0)>0 ? C.red : n.color}
              strokeWidth={2}/>
            <circle cx={n.x} cy={n.y} r={20} fill={n.color} opacity={0.1}/>
            <text x={n.x} y={n.y-2} textAnchor="middle"
              dominantBaseline="middle" fontSize={13}>📱</text>
            <text x={n.x} y={n.y+30} textAnchor="middle"
              fill={C.text} fontSize={8} fontWeight={600}>{shortLabel}</text>
            <text x={n.x} y={n.y+40} textAnchor="middle"
              fill={C.muted} fontSize={7} fontFamily="monospace">{n.id}</text>
            <text x={n.x} y={n.y+50} textAnchor="middle"
              fill={C.muted} fontSize={7}>{n.packet_count} pkts</text>
            {(n.unencrypted||0)>0 && (
              <g>
                <circle cx={n.x+16} cy={n.y-16} r={8} fill={C.red} opacity={0.9}/>
                <text x={n.x+16} y={n.y-16} textAnchor="middle"
                  dominantBaseline="middle" fontSize={9} fill="white">!</text>
              </g>
            )}
          </g>
        );
      })}

      {/* Controller / Coordinator nodes */}
      {Object.values(positioned).filter(n =>
        n.role === "coordinator" || n.role === "controller" || n.role === "central"
      ).map(n => {
        const typeLabel = n.device_type || n.role?.toUpperCase() || "CTRL";
        return (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={30}
              fill={C.surface} stroke={n.color} strokeWidth={2.5}/>
            <circle cx={n.x} cy={n.y} r={30} fill={n.color} opacity={0.12}/>
            <circle cx={n.x} cy={n.y} r={36} fill="none"
              stroke={n.color} strokeWidth={1}
              strokeDasharray="4,6" opacity={0.35}/>
            <text x={n.x} y={n.y-6} textAnchor="middle"
              dominantBaseline="middle" fontSize={16}>🔧</text>
            <text x={n.x} y={n.y+12} textAnchor="middle"
              fill={n.color} fontSize={8} fontWeight={700}>
              {typeLabel.length>14?typeLabel.slice(0,13)+"…":typeLabel}
            </text>
            <text x={n.x} y={n.y+38} textAnchor="middle"
              fill={C.muted} fontSize={8} fontFamily="monospace">{n.id}</text>
            <text x={n.x} y={n.y+48} textAnchor="middle"
              fill={C.muted} fontSize={7}>{n.packet_count} pkts</text>
          </g>
        );
      })}

      {/* Legend */}
      <g>
        <line x1={12} y1={H-14} x2={28} y2={H-14}
          stroke={C.accent} strokeWidth={2}/>
        <text x={33} y={H-10} fill={C.muted} fontSize={8}>Encrypted</text>
        <line x1={110} y1={H-14} x2={126} y2={H-14}
          stroke={C.red} strokeWidth={2} strokeDasharray="5,4"/>
        <text x={131} y={H-10} fill={C.muted} fontSize={8}>Unencrypted</text>
        <text x={230} y={H-10} fill={C.muted} fontSize={8}>
          Line thickness = traffic volume
        </text>
      </g>
    </svg>
  );
}

// ── DeviceBadge ──────────────────────────────────────────────────────────────
function DeviceBadge({ label, isCtrl, color, secure, addr }) {
  return (
    <div style={{display:"flex",alignItems:"center",gap:6,
      background:C.card,border:`1px solid ${secure?color+"40":C.red+"40"}`,
      borderRadius:8,padding:"6px 10px"}}>
      <span style={{fontSize:12}}>{isCtrl?"🔧":"📱"}</span>
      <div>
        <div style={{fontSize:11,color:C.text,fontWeight:600}}>{label}</div>
        {addr && <div style={{fontSize:9,color:C.muted,fontFamily:"monospace"}}>{addr}</div>}
      </div>
      <div style={{width:6,height:6,borderRadius:"50%",flexShrink:0,
        background:secure?color:C.red,
        boxShadow:`0 0 4px ${secure?color:C.red}`}}/>
    </div>
  );
}

// ── Statistics Page ───────────────────────────────────────────────────────────
function StatisticsPage({ results }) {
  const stats = {
    totalFiles:0, totalVulns:0,
    bySeverity:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0},
    byProtocol:{}, totalPackets:0, encrypted:0, unencrypted:0, totalDevices:0,
  };
  results.forEach(fr => {
    // أضف كل البروتوكولات المفحوصة حتى لو ما رجعوا من الـ backend
    const scannedProtocols = fr.protocols || [];
    scannedProtocols.forEach(p => {
      if(!stats.byProtocol[p]) stats.byProtocol[p]={vulns:0,packets:0};
    });
    fr.results?.forEach(r => {
      // أضف البروتوكول حتى لو ما فيه ثغرات
      if(!stats.byProtocol[r.protocol]) stats.byProtocol[r.protocol]={vulns:0,packets:0};
      r.vulns?.forEach(v => {
        stats.totalVulns++;
        if(stats.bySeverity[v.severity]!==undefined) stats.bySeverity[v.severity]++;
        stats.byProtocol[r.protocol].vulns++;
      });
      const s = r.statistics||{};
      // كل بروتوكول عنده key مختلف للعدد الحقيقي
      let pkts = 0;
      if (r.protocol === "Zigbee")       pkts = s.zigbee || s.zigbee_frames || 0;
      else if (r.protocol === "BLE")     pkts = s.ble || s.data_packets || s.advertisements || 0;
      else if (r.protocol === "Z-Wave")  pkts = s.zwave_frames || s.total_packets || 0;
      else pkts = s.total_packets || s.total || 0;
      stats.totalPackets += pkts;
      stats.encrypted   += s.encrypted||s.s0_frames||0;
      stats.unencrypted += s.unencrypted||0;
      if(!stats.byProtocol[r.protocol]) stats.byProtocol[r.protocol]={vulns:0,packets:0};
      stats.byProtocol[r.protocol].packets = (stats.byProtocol[r.protocol].packets||0)+pkts;
      stats.totalDevices += r.topology?.nodes?.length||0;
    });
  });
  stats.totalFiles = results.length;

  const encPct = stats.totalPackets>0 ? Math.round(stats.encrypted/stats.totalPackets*100) : 0;
  const sevColors = {CRITICAL:C.red,HIGH:C.orange,MEDIUM:C.yellow,LOW:C.green};
  const protoColors = {Zigbee:C.yellow,BLE:C.accent,"Z-Wave":C.green};
  const maxVulns = Math.max(...Object.values(stats.byProtocol).map(p=>p.vulns),1);

  return (
    <div style={{animation:"fadeUp .3s ease"}}>
      <div style={{marginBottom:24}}>
        <div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:11,
          color:C.accent,letterSpacing:2,marginBottom:4}}>STATISTICS DASHBOARD</div>
        <div style={{fontSize:12,color:C.muted}}>Comprehensive analysis of all scanned files</div>
      </div>

      {/* KPI cards */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
        {[
          {label:"Files Scanned",   value:stats.totalFiles,   color:C.accent, icon:"📁"},
          {label:"Vulnerabilities", value:stats.totalVulns,   color:stats.totalVulns>0?C.red:C.green, icon:"⚠"},
          {label:"Devices Found",   value:stats.totalDevices, color:C.yellow, icon:"📱"},
          {label:"Packets Analyzed",value:stats.totalPackets, color:C.muted,  icon:"📦"},
        ].map((kpi,i)=>(
          <div key={i} style={{background:C.surface,border:`1px solid ${kpi.color}30`,
            borderRadius:12,padding:"18px 20px",position:"relative",overflow:"hidden"}}>
            <div style={{position:"absolute",top:12,right:16,fontSize:22,opacity:0.5}}>{kpi.icon}</div>
            <div style={{fontSize:10,color:C.muted,letterSpacing:2,marginBottom:8}}>
              {kpi.label.toUpperCase()}
            </div>
            <div style={{fontSize:32,fontWeight:800,color:kpi.color,
              fontFamily:"'IBM Plex Mono',monospace",lineHeight:1}}>{kpi.value}</div>
            <div style={{position:"absolute",bottom:0,left:0,right:0,height:2,
              background:`linear-gradient(90deg,${kpi.color}60,transparent)`}}/>
          </div>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        {/* Severity bars */}
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20}}>
          <div style={{fontSize:10,color:C.muted,letterSpacing:2,marginBottom:16}}>SEVERITY BREAKDOWN</div>
          {Object.entries(stats.bySeverity).map(([sev,cnt])=>{
            const max = Math.max(...Object.values(stats.bySeverity),1);
            return (
              <div key={sev} style={{marginBottom:12}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:5}}>
                  <span style={{fontSize:10,fontWeight:700,color:sevColors[sev],letterSpacing:1}}>{sev}</span>
                  <span style={{fontSize:11,fontWeight:700,color:sevColors[sev],fontFamily:"monospace"}}>{cnt}</span>
                </div>
                <div style={{height:6,background:C.card,borderRadius:3,overflow:"hidden"}}>
                  <div style={{height:"100%",width:`${Math.round(cnt/max*100)}%`,
                    background:`linear-gradient(90deg,${sevColors[sev]},${sevColors[sev]}80)`,
                    borderRadius:3,boxShadow:`0 0 8px ${sevColors[sev]}60`}}/>
                </div>
              </div>
            );
          })}
        </div>

        {/* Encryption donut */}
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20}}>
          <div style={{fontSize:10,color:C.muted,letterSpacing:2,marginBottom:16}}>ENCRYPTION STATUS</div>
          <div style={{display:"flex",alignItems:"center",gap:20}}>
            <svg width={120} height={120} viewBox="0 0 120 120">
              <circle cx={60} cy={60} r={45} fill="none" stroke={C.card} strokeWidth={18}/>
              {encPct>0 && <circle cx={60} cy={60} r={45} fill="none" stroke={C.green}
                strokeWidth={18}
                strokeDasharray={`${encPct*2.827} ${282.7-encPct*2.827}`}
                strokeDashoffset={70.7} strokeLinecap="butt"
                style={{filter:`drop-shadow(0 0 6px ${C.green})`}}/>}
              {encPct<100 && <circle cx={60} cy={60} r={45} fill="none" stroke={C.red}
                strokeWidth={18}
                strokeDasharray={`${(100-encPct)*2.827} ${282.7-(100-encPct)*2.827}`}
                strokeDashoffset={70.7-encPct*2.827} strokeLinecap="butt" opacity={0.8}/>}
              <text x={60} y={55} textAnchor="middle" fill={C.text} fontSize={18}
                fontWeight={700} fontFamily="monospace">{encPct}%</text>
              <text x={60} y={72} textAnchor="middle" fill={C.muted} fontSize={8}>encrypted</text>
            </svg>
            <div style={{flex:1,display:"flex",flexDirection:"column",gap:10}}>
              {[{color:C.green,label:"Encrypted",val:stats.encrypted},
                {color:C.red,label:"Unencrypted",val:stats.unencrypted}].map(item=>(
                <div key={item.label} style={{display:"flex",alignItems:"center",gap:8}}>
                  <div style={{width:10,height:10,borderRadius:2,background:item.color,
                    boxShadow:`0 0 6px ${item.color}`}}/>
                  <div>
                    <div style={{fontSize:11,color:C.text,fontWeight:600}}>{item.label}</div>
                    <div style={{fontSize:10,color:C.muted,fontFamily:"monospace"}}>{item.val} pkts</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Bar chart */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20,marginBottom:16}}>
        <div style={{fontSize:10,color:C.muted,letterSpacing:2,marginBottom:20}}>VULNERABILITIES BY PROTOCOL</div>
        <div style={{display:"flex",alignItems:"flex-end",gap:16,height:140}}>
          {Object.entries(stats.byProtocol).map(([proto,data])=>{
            const color = protoColors[proto]||C.muted;
            const barH = Math.round(data.vulns/maxVulns*100);
            return (
              <div key={proto} style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:8}}>
                <div style={{fontSize:11,color,fontWeight:700,fontFamily:"monospace"}}>{data.vulns}</div>
                <div style={{width:"100%",height:100,display:"flex",alignItems:"flex-end",justifyContent:"center"}}>
                  <div style={{width:"60%",height:`${Math.max(barH,4)}%`,minHeight:4,
                    background:`linear-gradient(180deg,${color},${color}50)`,
                    borderRadius:"4px 4px 0 0",boxShadow:`0 0 12px ${color}40`}}/>
                </div>
                <div style={{fontSize:10,color,fontWeight:700,letterSpacing:1}}>{proto}</div>
                <div style={{fontSize:9,color:C.muted}}>{data.packets} pkts</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Risk scores */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20}}>
        <div style={{fontSize:10,color:C.muted,letterSpacing:2,marginBottom:14}}>RISK SCORES BY FILE</div>
        {results.map((fr,fi)=>(
          <div key={fi} style={{marginBottom:14}}>
            <div style={{fontSize:10,color:C.accent,fontFamily:"monospace",marginBottom:8}}>📄 {fr.file}</div>
            {fr.results?.filter(r=>typeof r.risk_score==="number").map(r=>{
              const color = riskColor(r.risk_score);
              return (
                <div key={r.protocol} style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
                  <div style={{width:60,fontSize:9,color:protoColors[r.protocol]||C.muted,fontWeight:700}}>
                    {r.protocol}
                  </div>
                  <div style={{flex:1,height:8,background:C.card,borderRadius:4}}>
                    <div style={{height:"100%",width:`${r.risk_score}%`,
                      background:`linear-gradient(90deg,${color},${color}80)`,
                      borderRadius:4,boxShadow:`0 0 6px ${color}60`}}/>
                  </div>
                  <div style={{width:40,fontSize:10,fontWeight:700,color,
                    fontFamily:"monospace",textAlign:"right"}}>{r.risk_score}</div>
                  <div style={{fontSize:9,fontWeight:700,color,letterSpacing:1,width:55}}>
                    {riskLabel(r.risk_score)}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Attack Chain Engine ───────────────────────────────────────────────────────

const ATTACK_CHAINS = [
  {
    id: "ZB-CHAIN-001",
    name: "Full Network Compromise",
    protocols: ["Zigbee"],
    requires: ["ZIGBEE-001", "ZIGBEE-004"],
    optional: ["ZIGBEE-002", "ZIGBEE-003"],
    severity: "CRITICAL",
    impact: "Complete control over all Zigbee devices",
    attacker: "Passive attacker within 100m radio range",
    steps: [
      { phase:"Reconnaissance", vuln:"ZIGBEE-001", icon:"👁",
        action:"Attacker uses a $20 CC2531 USB sniffer to passively capture all unencrypted Zigbee traffic",
        result:"Full visibility into device commands, sensor readings, and network topology" },
      { phase:"Credential Harvest", vuln:"ZIGBEE-002", icon:"🔑", optional:true,
        action:"Attacker captures the network key transmitted in plaintext during device joining",
        result:"Attacker now possesses the master network key — can decrypt all past and future traffic" },
      { phase:"Replay Attack", vuln:"ZIGBEE-004", icon:"🔄",
        action:"Attacker replays captured 'unlock door' or 'disable alarm' commands",
        result:"Physical security bypass — doors unlocked, alarms disabled without authentication" },
      { phase:"Persistence", vuln:"ZIGBEE-003", icon:"🏠", optional:true,
        action:"Attacker joins the network using the stolen key during an open join window",
        result:"Permanent unauthorized device in the network — full ongoing control" },
    ],
    realWorld:"Similar to the 2020 Zigbee vulnerability used to hijack Philips Hue bulbs (Check Point Research)",
  },
  {
    id: "ZB-CHAIN-002",
    name: "Denial of Service Attack",
    protocols: ["Zigbee"],
    requires: ["ZIGBEE-007"],
    optional: ["ZIGBEE-008", "ZIGBEE-010"],
    severity: "HIGH",
    impact: "Complete network disruption — all devices unresponsive",
    attacker: "Attacker within radio range with basic hardware",
    steps: [
      { phase:"Network Mapping", vuln:"ZIGBEE-010", icon:"🗺", optional:true,
        action:"Attacker floods route request packets to map the network topology",
        result:"Full network map obtained — coordinator and all router addresses identified" },
      { phase:"Packet Flooding", vuln:"ZIGBEE-007", icon:"💥",
        action:"Attacker transmits thousands of packets per second targeting the coordinator",
        result:"Coordinator overwhelmed — stops processing legitimate device commands" },
      { phase:"Beacon Storm", vuln:"ZIGBEE-008", icon:"📡", optional:true,
        action:"Attacker broadcasts excessive beacon frames causing all routers to enter scan mode",
        result:"All devices disconnect from network — complete network outage" },
    ],
    realWorld:"IoT DoS attacks caused $300M in damages during the 2016 Mirai botnet attack",
  },
  {
    id: "BLE-CHAIN-001",
    name: "Medical Device Data Theft",
    protocols: ["BLE"],
    requires: ["BLE-006"],
    optional: ["BLE-003", "BLE-005"],
    severity: "CRITICAL",
    impact: "Patient health data exposed — HIPAA violation",
    attacker: "Passive attacker in hospital waiting room",
    steps: [
      { phase:"Device Discovery", vuln:"BLE-005", icon:"📍", optional:true,
        action:"Attacker scans for BLE advertisements — devices broadcast static MAC addresses",
        result:"All medical BLE devices identified and located within range" },
      { phase:"Silent Connection", vuln:"BLE-003", icon:"🤝", optional:true,
        action:"Attacker connects using Just Works pairing — no user confirmation required",
        result:"Unauthorized connection established to medical sensor without any alert" },
      { phase:"Data Exfiltration", vuln:"BLE-006", icon:"📋",
        action:"Attacker reads all GATT characteristics — heart rate, blood pressure, glucose levels",
        result:"Complete patient health profile extracted silently in seconds" },
    ],
    realWorld:"FDA issued warnings in 2021 about BLE vulnerabilities in insulin pumps and pacemakers",
  },
  {
    id: "BLE-CHAIN-002",
    name: "Smart Lock Physical Bypass",
    protocols: ["BLE"],
    requires: ["BLE-006", "BLE-008"],
    optional: ["BLE-001"],
    severity: "CRITICAL",
    impact: "Physical premises access without credentials",
    attacker: "Attacker outside locked door with laptop",
    steps: [
      { phase:"Session Capture", vuln:"BLE-001", icon:"🗝", optional:true,
        action:"Attacker forces weak session key using BLUFFS attack on the lock's BLE connection",
        result:"All BLE session traffic can be decrypted in real-time" },
      { phase:"Command Interception", vuln:"BLE-006", icon:"📡",
        action:"Attacker captures the unencrypted 'unlock' GATT write command",
        result:"Exact byte sequence for unlock command obtained" },
      { phase:"Relay Attack", vuln:"BLE-008", icon:"🚪",
        action:"Attacker relays BLE link layer — phone near owner triggers unlock from 100m away",
        result:"Door unlocked — physical access achieved without owner's knowledge" },
    ],
    realWorld:"NCC Group demonstrated relay attacks on Tesla Model 3 and Kwikset smart locks in 2022",
  },
  {
    id: "BLE-CHAIN-003",
    name: "Device Crash & Service Denial",
    protocols: ["BLE"],
    requires: ["BLE-009"],
    optional: ["BLE-011"],
    severity: "HIGH",
    impact: "Critical IoT devices rendered non-functional",
    attacker: "Attacker within BLE range",
    steps: [
      { phase:"Connection Flood", vuln:"BLE-011", icon:"🌊", optional:true,
        action:"Attacker sends hundreds of connection requests per minute",
        result:"Device connection table overflows — stops accepting legitimate connections" },
      { phase:"Stack Crash", vuln:"BLE-009", icon:"💣",
        action:"Attacker sends malformed L2CAP packets — triggers SweynTooth vulnerability",
        result:"BLE firmware crashes — device requires physical reset to recover" },
    ],
    realWorld:"SweynTooth affected 480+ million devices across TI, Nordic, Dialog, NXP, and Cypress chips",
  },
  {
    id: "ZW-CHAIN-001",
    name: "Smart Home Takeover",
    protocols: ["Z-Wave"],
    requires: ["ZWAVE-001", "ZWAVE-007"],
    optional: ["ZWAVE-008", "ZWAVE-009"],
    severity: "CRITICAL",
    impact: "Full control of all Z-Wave smart home devices",
    attacker: "Attacker within 100m of target home",
    steps: [
      { phase:"Network Discovery", vuln:"ZWAVE-009", icon:"🏠",
        action:"Attacker captures Z-Wave frames — Home ID is always in plaintext header",
        result:"Network identified, all node addresses mapped without joining the network" },
      { phase:"Traffic Interception", vuln:"ZWAVE-001", icon:"👁",
        action:"Attacker captures unencrypted application frames from legacy devices",
        result:"All device commands visible — lock codes, thermostat settings, motion patterns" },
      { phase:"Key Reset Attack", vuln:"ZWAVE-007", icon:"🔑",
        action:"Attacker sends SEC_SCHEME_GET twice to trigger key re-negotiation on door lock",
        result:"Lock's S0 key transmitted in plaintext — attacker has permanent access" },
      { phase:"Replay Takeover", vuln:"ZWAVE-008", icon:"🔄", optional:true,
        action:"Attacker replays captured 'unlock' and 'disarm alarm' commands",
        result:"Physical access achieved — all smart home devices under attacker's control" },
    ],
    realWorld:"CVE-2020-9057: Affected 100M+ Z-Wave devices in smart homes, hotels, and hospitals",
  },
  {
    id: "ZW-CHAIN-002",
    name: "Zero-Key Inclusion Attack",
    protocols: ["Z-Wave"],
    requires: ["ZWAVE-010"],
    optional: ["ZWAVE-003", "ZWAVE-005"],
    severity: "CRITICAL",
    impact: "Rogue device permanently joined to network",
    attacker: "Attacker near target during device pairing",
    steps: [
      { phase:"Timing the Attack", vuln:"ZWAVE-005", icon:"⏱", optional:true,
        action:"Attacker waits for inclusion window when user is pairing a new device",
        result:"30-second inclusion window identified — attack window open" },
      { phase:"Zero-Key Injection", vuln:"ZWAVE-010", icon:"🔓",
        action:"Attacker sends S0 inclusion — network key transmitted with all-zero temporary key",
        result:"Network key captured using known zero-key — attacker fully authenticated" },
      { phase:"Permanent Access", vuln:"ZWAVE-003", icon:"🕵", optional:true,
        action:"Attacker rogue device accepted — downgraded to S0 instead of S2",
        result:"Persistent unauthorized device — survives reboots, monitors all traffic" },
    ],
    realWorld:"Demonstrated at DEF CON 2019 — affects all Z-Wave devices supporting S0 legacy pairing",
  },
  {
    id: "ZB-CHAIN-004",
    name: "Beacon Flood & Traffic Interception",
    protocols: ["Zigbee"],
    requires: ["ZIGBEE-001", "ZIGBEE-008"],
    optional: ["ZIGBEE-007", "ZIGBEE-004"],
    severity: "HIGH",
    impact: "Network disruption combined with full traffic visibility",
    attacker: "Attacker within Zigbee radio range with SDR hardware",
    steps: [
      { phase:"Traffic Interception", vuln:"ZIGBEE-001", icon:"👁",
        action:"Attacker passively captures all unencrypted Zigbee frames — device commands fully visible",
        result:"Complete network map obtained — device types, addresses, and command patterns identified" },
      { phase:"Beacon Flooding", vuln:"ZIGBEE-008", icon:"📡",
        action:"Attacker broadcasts excessive beacon frames to overwhelm all routers in the network",
        result:"Routers enter continuous scan mode — normal traffic disrupted, devices lose connectivity" },
      { phase:"Selective Replay", vuln:"ZIGBEE-004", icon:"🔄", optional:true,
        action:"During the confusion, attacker replays previously captured critical commands",
        result:"Doors unlocked or alarms disabled while network appears to be experiencing interference" },
    ],
    realWorld:"Combined sniffing and jamming attacks on Zigbee networks demonstrated at Black Hat 2017",
  },
  {
    id: "ZB-CHAIN-005",
    name: "Unencrypted Network Reconnaissance",
    protocols: ["Zigbee"],
    requires: ["ZIGBEE-001"],
    optional: ["ZIGBEE-008", "ZIGBEE-009"],
    severity: "HIGH",
    impact: "Full network visibility — attacker maps all devices and behaviors",
    attacker: "Passive attacker with $20 CC2531 USB sniffer",
    steps: [
      { phase:"Passive Sniffing", vuln:"ZIGBEE-001", icon:"👁",
        action:"Attacker captures all unencrypted frames without transmitting a single packet",
        result:"All device types, addresses, and command patterns recorded silently" },
      { phase:"Device Profiling", vuln:"ZIGBEE-009", icon:"📊", optional:true,
        action:"Attacker analyzes join/leave announcements to identify when new devices are added",
        result:"Optimal attack window identified — knows exactly when to inject malicious device" },
      { phase:"Network Disruption", vuln:"ZIGBEE-008", icon:"💥", optional:true,
        action:"Attacker uses beacon flood to force all devices to re-announce — harvests more data",
        result:"Complete device inventory obtained with minimal effort" },
    ],
    realWorld:"Zigbee sniffing tools like KillerBee have been publicly available since 2009 — no specialized skills required",
  },
  {
    id: "BLE-CHAIN-004",
    name: "Device Tracking & Privacy Breach",
    protocols: ["BLE"],
    requires: ["BLE-005"],
    optional: ["BLE-001", "BLE-011"],
    severity: "HIGH",
    impact: "User location and behavior patterns exposed",
    attacker: "Passive attacker with BLE scanner in public area",
    steps: [
      { phase:"Passive Scanning", vuln:"BLE-005", icon:"📡",
        action:"Attacker deploys BLE scanner — devices broadcast static MAC addresses continuously",
        result:"All nearby devices fingerprinted and tracked across time and location" },
      { phase:"Session Interception", vuln:"BLE-001", icon:"🔓", optional:true,
        action:"Attacker uses BLUFFS attack to force weak session keys on tracked devices",
        result:"Historical and future communication sessions can be decrypted" },
      { phase:"Resource Exhaustion", vuln:"BLE-011", icon:"🌊", optional:true,
        action:"Attacker floods connection requests to drain device battery",
        result:"Tracked device battery depleted — device goes offline for maintenance" },
    ],
    realWorld:"Apple and Google implemented MAC address randomization in iOS/Android to counter this exact attack vector",
  },
  {
    id: "BLE-CHAIN-005",
    name: "Session Hijacking via Weak Keys",
    protocols: ["BLE"],
    requires: ["BLE-001"],
    optional: ["BLE-005", "BLE-011"],
    severity: "CRITICAL",
    impact: "All BLE communications decrypted — past and future",
    attacker: "MITM attacker within BLE range",
    steps: [
      { phase:"Target Identification", vuln:"BLE-005", icon:"🎯", optional:true,
        action:"Static MAC addresses allow attacker to identify and target specific devices",
        result:"High-value targets identified — medical devices, smart locks, payment terminals" },
      { phase:"BLUFFS Key Reduction", vuln:"BLE-001", icon:"🔑",
        action:"Attacker exploits CVE-2023-24023 to force session key derivation with minimal entropy",
        result:"All session keys reduced to predictable values — brute-forceable in seconds" },
      { phase:"DoS After Compromise", vuln:"BLE-011", icon:"💥", optional:true,
        action:"After extracting all needed data, attacker floods device to cover tracks",
        result:"Device crashes — logs cleared, attack evidence destroyed" },
    ],
    realWorld:"BLUFFS attack demonstrated at IEEE S&P 2024 — affects all Bluetooth 4.0-5.4 devices",
  },
  {
    id: "CROSS-CHAIN-001",
    name: "Multi-Protocol Home Invasion",
    protocols: ["Zigbee", "BLE", "Z-Wave"],
    requires: ["ZIGBEE-001", "BLE-006", "ZWAVE-001"],
    optional: ["ZIGBEE-004", "ZWAVE-007"],
    severity: "CRITICAL",
    impact: "Complete smart home compromise across all protocols",
    attacker: "Advanced attacker with multi-protocol SDR hardware",
    steps: [
      { phase:"BLE Reconnaissance", vuln:"BLE-006", icon:"📊",
        action:"Attacker reads BLE GATT data — discovers home occupancy patterns and device schedule",
        result:"Knows when house is empty — optimal attack timing identified" },
      { phase:"Zigbee Sniffing", vuln:"ZIGBEE-001", icon:"🗺",
        action:"Captures unencrypted Zigbee traffic — identifies motion sensors and door contacts",
        result:"Complete map of security devices — knows blind spots in coverage" },
      { phase:"Z-Wave Lock Bypass", vuln:"ZWAVE-001", icon:"🚪",
        action:"Intercepts unencrypted Z-Wave lock commands — extracts unlock sequences",
        result:"Physical access to home achieved silently" },
      { phase:"Alarm Suppression", vuln:"ZIGBEE-004", icon:"🔕", optional:true,
        action:"Replays captured Zigbee commands to disable alarm sensors before entry",
        result:"All detection systems bypassed — attacker enters undetected" },
    ],
    realWorld:"Compound IoT attacks targeting smart homes increased 300% in 2023 (Kaspersky ICS-CERT)",
  },
];

function buildAttackChains(results) {
  const foundVulns = new Set();
  const foundProtocols = new Set();
  results.forEach(fr => {
    fr.results?.forEach(r => {
      foundProtocols.add(r.protocol);
      r.vulns?.forEach(v => foundVulns.add(v.id));
    });
  });
  const matched = [];
  for (const chain of ATTACK_CHAINS) {
    const hasRequired = chain.requires.every(id => foundVulns.has(id));
    const hasProtocol = chain.protocols.some(p => foundProtocols.has(p));
    if (hasRequired && hasProtocol) {
      const optionalFound = chain.optional.filter(id => foundVulns.has(id)).length;
      const coverage = Math.round(
        ((chain.requires.length + optionalFound) /
         (chain.requires.length + chain.optional.length)) * 100
      );
      matched.push({ ...chain, coverage, optionalFound });
    }
  }
  const sevOrder = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
  return matched.sort((a,b) =>
    sevOrder[a.severity] - sevOrder[b.severity] || b.coverage - a.coverage
  );
}

function AttackChainPage({ results }) {
  const [selectedChain, setSelectedChain] = useState(null);
  const chains = buildAttackChains(results);
  const sevColors = { CRITICAL:C.red, HIGH:C.orange, MEDIUM:C.yellow, LOW:C.green };
  const protoCol  = { Zigbee:C.yellow, BLE:C.accent, "Z-Wave":C.green };
  const vulnMap = {};
  results.forEach(fr => fr.results?.forEach(r => r.vulns?.forEach(v => { vulnMap[v.id]=v; })));

  if (chains.length === 0) {
    return (
      <div style={{animation:"fadeUp .3s ease"}}>
        <div style={{marginBottom:20}}>
          <div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:11,
            color:C.accent,letterSpacing:2,marginBottom:4}}>ATTACK CHAIN ANALYSIS</div>
          <div style={{fontSize:12,color:C.muted}}>
            Correlates detected vulnerabilities into realistic attack scenarios
          </div>
        </div>
        <div style={{background:C.surface,border:`1px solid ${C.border}`,
          borderRadius:12,padding:40,textAlign:"center"}}>
          <div style={{fontSize:32,marginBottom:12}}>🛡</div>
          <div style={{fontSize:14,color:C.green,fontWeight:600,marginBottom:8}}>
            No Attack Chains Detected
          </div>
          <div style={{fontSize:12,color:C.muted}}>
            No correlated vulnerability patterns found. The network appears properly secured.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{animation:"fadeUp .3s ease"}}>
      <div style={{marginBottom:20}}>
        <div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:11,
          color:C.accent,letterSpacing:2,marginBottom:4}}>ATTACK CHAIN ANALYSIS</div>
        <div style={{fontSize:12,color:C.muted}}>
          {chains.length} attack scenario{chains.length!==1?"s":""} identified — click to explore
        </div>
      </div>

      <div style={{display:"grid",
        gridTemplateColumns:selectedChain?"320px 1fr":"repeat(auto-fill,minmax(320px,1fr))",
        gap:16,alignItems:"start"}}>

        {/* Chain list */}
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          {chains.map(chain => {
            const sc = sevColors[chain.severity]||C.muted;
            const isSelected = selectedChain?.id === chain.id;
            return (
              <div key={chain.id}
                onClick={()=>setSelectedChain(isSelected?null:chain)}
                style={{background:isSelected?`${sc}12`:C.surface,
                  border:`1px solid ${isSelected?sc+"60":C.border}`,
                  borderLeft:`3px solid ${sc}`,borderRadius:10,
                  padding:"14px 16px",cursor:"pointer",transition:"all .2s",
                  boxShadow:isSelected?`0 0 16px ${sc}20`:"none"}}>
                <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}>
                  <span style={{fontSize:8,fontWeight:700,letterSpacing:1.5,color:sc,
                    background:`${sc}20`,border:`1px solid ${sc}40`,
                    padding:"2px 7px",borderRadius:4}}>{chain.severity}</span>
                  {chain.protocols.map(p=>(
                    <span key={p} style={{fontSize:8,fontWeight:700,
                      color:protoCol[p]||C.muted,background:`${protoCol[p]||C.muted}15`,
                      border:`1px solid ${protoCol[p]||C.muted}40`,
                      padding:"2px 7px",borderRadius:4}}>{p}</span>
                  ))}
                </div>
                <div style={{fontSize:13,fontWeight:700,color:C.text,marginBottom:5}}>
                  {chain.name}
                </div>
                <div style={{fontSize:10,color:C.muted,lineHeight:1.4,marginBottom:8}}>
                  {chain.impact}
                </div>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <div style={{flex:1,height:3,background:C.card,borderRadius:2}}>
                    <div style={{height:"100%",width:`${chain.coverage}%`,
                      background:`linear-gradient(90deg,${sc},${sc}80)`,
                      borderRadius:2}}/>
                  </div>
                  <span style={{fontSize:9,color:sc,fontWeight:700,
                    fontFamily:"monospace"}}>{chain.coverage}%</span>
                </div>
                <div style={{fontSize:8,color:C.muted,marginTop:3}}>
                  {chain.requires.length} required + {chain.optionalFound}/{chain.optional.length} optional matched
                </div>
              </div>
            );
          })}
        </div>

        {/* Chain detail */}
        {selectedChain && (
          <div style={{background:C.surface,border:`1px solid ${C.border}`,
            borderRadius:12,padding:20,animation:"fadeUp .2s ease"}}>
            <div style={{marginBottom:18}}>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                <span style={{fontSize:10,fontWeight:700,letterSpacing:1.5,
                  color:sevColors[selectedChain.severity],
                  background:`${sevColors[selectedChain.severity]}20`,
                  border:`1px solid ${sevColors[selectedChain.severity]}40`,
                  padding:"3px 9px",borderRadius:4}}>{selectedChain.severity}</span>
                <span style={{fontFamily:"monospace",fontSize:11,color:C.muted}}>
                  {selectedChain.id}
                </span>
              </div>
              <div style={{fontSize:20,fontWeight:700,color:C.text,marginBottom:8}}>
                {selectedChain.name}
              </div>
              <div style={{fontSize:13,color:C.text,marginBottom:6}}>
                🎯 {selectedChain.impact}
              </div>
              <div style={{fontSize:13,color:C.muted}}>
                👤 {selectedChain.attacker}
              </div>
            </div>

            <div style={{fontSize:11,color:C.muted,letterSpacing:2,marginBottom:14}}>
              ATTACK TIMELINE
            </div>

            {selectedChain.steps.map((step,si) => {
              const sc = sevColors[selectedChain.severity];
              const isOpt = step.optional;
              const vulnData = vulnMap[step.vuln];
              return (
                <div key={si} style={{display:"flex",gap:14,marginBottom:0}}>
                  <div style={{display:"flex",flexDirection:"column",alignItems:"center",flexShrink:0}}>
                    <div style={{width:38,height:38,borderRadius:"50%",
                      background:isOpt?`${sc}15`:`${sc}30`,
                      border:`2px solid ${isOpt?sc+"50":sc}`,
                      display:"flex",alignItems:"center",justifyContent:"center",
                      fontSize:18,flexShrink:0,
                      boxShadow:isOpt?"none":`0 0 10px ${sc}40`}}>{step.icon}</div>
                    {si < selectedChain.steps.length-1 && (
                      <div style={{width:3,flex:1,minHeight:20,
                        background:isOpt
                          ?`linear-gradient(180deg,${sc}30,${sc}10)`
                          :`linear-gradient(180deg,${sc},${sc}50)`,
                        margin:"4px 0",borderRadius:2,
                        boxShadow:isOpt?"none":`0 0 6px ${sc}40`}}/>
                    )}
                  </div>
                  <div style={{flex:1,paddingBottom:18}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:7}}>
                      <span style={{fontSize:12,fontWeight:700,
                        color:isOpt?C.muted:sc,letterSpacing:1}}>
                        {si+1}. {step.phase}
                      </span>
                      {isOpt && (
                        <span style={{fontSize:8,color:C.muted,background:C.card,
                          border:`1px solid ${C.border}`,padding:"1px 6px",borderRadius:4}}>
                          OPTIONAL
                        </span>
                      )}
                      <span style={{fontSize:9,fontFamily:"monospace",color:C.accent,
                        background:`${C.accent}10`,border:`1px solid ${C.accent}30`,
                        padding:"2px 7px",borderRadius:4,fontWeight:700}}>{step.vuln}</span>
                    </div>
                    <div style={{background:C.card,borderRadius:8,padding:"12px 14px",marginBottom:7,
                      border:`1px solid ${isOpt?C.border:sc+"20"}`}}>
                      <div style={{fontSize:12,color:C.text,lineHeight:1.6,marginBottom:7}}>
                        {step.action}
                      </div>
                      <div style={{fontSize:11,color:sc,fontWeight:700,
                        borderTop:`1px solid ${sc}20`,paddingTop:6}}>
                        → {step.result}
                      </div>
                    </div>
                    {vulnData && (
                      <div style={{fontSize:10,color:C.muted,fontFamily:"monospace",
                        background:`${C.accent}08`,border:`1px solid ${C.accent}20`,
                        borderRadius:4,padding:"5px 10px"}}>
                        📊 {vulnData.evidence}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {selectedChain.realWorld && (
              <div style={{background:`${C.orange}10`,border:`1px solid ${C.orange}30`,
                borderRadius:8,padding:"12px 14px",marginTop:4}}>
                <div style={{fontSize:11,color:C.orange,fontWeight:700,
                  letterSpacing:1,marginBottom:4}}>REAL WORLD REFERENCE</div>
                <div style={{fontSize:13,color:C.text,lineHeight:1.5}}>
                  {selectedChain.realWorld}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ProtocolModal({ files, protocols, setProtocols, onCancel, onScan }) {
  const selected = Object.entries(protocols).filter(([,v])=>v).map(([k])=>k);
  return (
    <div style={{position:"fixed",inset:0,zIndex:1000,
      background:"rgba(0,0,0,0.75)",
      display:"flex",alignItems:"center",justifyContent:"center",
      backdropFilter:"blur(4px)"}}>
      <div style={{background:C.surface,border:`1px solid ${C.accent}60`,
        borderRadius:16,padding:"28px 32px",width:360,
        boxShadow:`0 0 40px ${C.accent}20`}}>

        {/* Title */}
        <div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:11,
          color:C.accent,letterSpacing:2,marginBottom:4}}>SELECT PROTOCOLS</div>
        <div style={{fontSize:12,color:C.muted,lineHeight:1.5,marginBottom:14}}>
          Choose which protocols to scan for vulnerabilities
        </div>

        {/* Files */}
        <div style={{background:C.card,borderRadius:8,padding:"8px 12px",
          marginBottom:18,border:`1px solid ${C.border}`}}>
          <div style={{fontSize:9,color:C.muted,letterSpacing:1,marginBottom:4}}>FILES</div>
          {files.map((f,i)=>(
            <div key={i} style={{fontSize:11,color:C.text,
              overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
              📄 {f.name}
            </div>
          ))}
        </div>

        {/* Protocol options */}
        <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:24}}>
          {Object.entries(protocols).map(([name, active])=>{
            const color = name==="Zigbee"?C.yellow:name==="BLE"?C.accent:C.green;
            const desc  = name==="Zigbee"?"IEEE 802.15.4 — Smart home mesh"
                        : name==="BLE"   ?"Bluetooth Low Energy — Wearables"
                        :                 "Z-Wave 900MHz — Smart locks & sensors";
            return (
              <div key={name}
                onClick={()=>setProtocols(p=>({...p,[name]:!p[name]}))}
                style={{display:"flex",alignItems:"center",gap:14,
                  background:active?`${color}12`:C.card,
                  border:`1px solid ${active?color+"60":C.border}`,
                  borderRadius:10,padding:"12px 14px",cursor:"pointer",
                  transition:"all .2s",
                  boxShadow:active?`0 0 10px ${color}15`:"none"}}>
                {/* Checkbox */}
                <div style={{width:18,height:18,borderRadius:4,flexShrink:0,
                  border:`2px solid ${active?color:C.muted}`,
                  background:active?color:"transparent",
                  display:"flex",alignItems:"center",justifyContent:"center",
                  transition:"all .2s"}}>
                  {active && <span style={{color:"#000",fontSize:11,fontWeight:900}}>✓</span>}
                </div>
                <div style={{flex:1}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3}}>
                    <div style={{width:7,height:7,borderRadius:"50%",
                      background:active?color:C.muted,
                      boxShadow:active?`0 0 6px ${color}`:"none",transition:"all .2s"}}/>
                    <span style={{fontSize:13,fontWeight:700,
                      color:active?color:C.muted,transition:"color .2s"}}>{name}</span>
                  </div>
                  <div style={{fontSize:10,color:C.muted,paddingLeft:15}}>{desc}</div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Buttons */}
        <div style={{display:"flex",gap:10}}>
          <button onClick={onCancel}
            style={{flex:1,padding:"10px",borderRadius:8,
              border:`1px solid ${C.border}`,background:"transparent",
              color:C.muted,fontSize:12,fontWeight:600,cursor:"pointer",
              fontFamily:"'Syne',sans-serif"}}>
            Cancel
          </button>
          <button
            disabled={selected.length===0}
            onClick={()=>onScan(selected)}
            style={{flex:2,padding:"10px",borderRadius:8,
              border:`1px solid ${selected.length?C.accent:C.border}`,
              background:selected.length
                ?`linear-gradient(135deg,${C.accent}30,${C.accent}15)`:"transparent",
              color:selected.length?C.accent:C.muted,
              fontSize:12,fontWeight:700,letterSpacing:1,
              cursor:selected.length?"pointer":"not-allowed",
              fontFamily:"'Syne',sans-serif",transition:"all .2s"}}>
            ▶ SCAN ({selected.join(", ")||"none"})
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [files,     setFiles]     = useState([]);
  const [scanning,  setScanning]  = useState(false);
  const [results,   setResults]   = useState([]);
  const [log,       setLog]       = useState([]);
  const [dragging,  setDragging]  = useState(false);
  const [backendOk, setBackendOk] = useState(null);
  const [genPdf,    setGenPdf]    = useState(false);
  const [protocols, setProtocols] = useState({
    "Zigbee": true, "BLE": true, "Z-Wave": true
  });
  const [showModal, setShowModal] = useState(false);
  const [page,      setPage]      = useState("scan"); // "scan" | "topology" | "stats" | "attack"
  const inputRef = useRef();
  const logRef   = useRef();

  useEffect(()=>{
    fetch(`${API}/health`).then(r=>r.json())
      .then(d=>setBackendOk(d.status==="ok")).catch(()=>setBackendOk(false));
  },[]);

  useEffect(()=>{
    if(logRef.current) logRef.current.scrollTop=logRef.current.scrollHeight;
  },[log]);

  const addLog = (msg,type="info")=>{
    const colors={info:C.muted,success:C.green,error:C.red,warn:C.yellow};
    setLog(prev=>[...prev,{msg,color:colors[type]||C.muted,time:new Date().toLocaleTimeString()}]);
  };

  const handleDrop=(e)=>{
    e.preventDefault(); setDragging(false);
    const dropped=Array.from(e.dataTransfer.files).filter(f=>f.name.match(/\.(pcap|pcapng)$/i));
    if(dropped.length){ setFiles(prev=>[...prev,...dropped]); setShowModal(true); }
  };

  const handleScan=async(selected)=>{
    if(!files.length) return;
    if(!selected?.length){ addLog("Select at least one protocol","error"); return; }
    setScanning(true); setResults([]); setLog([]);
    addLog(`Starting scan: ${files.length} file(s) — ${selected.join(", ")}`,"info");
    for(const file of files){
      addLog(`→ Uploading ${file.name}...`,"info");
      const fd=new FormData();
      fd.append("file",file);
      fd.append("protocols", selected.join(","));
      try{
        const res=await fetch(`${API}/scan`,{method:"POST",body:fd});
        const data=await res.json();
        if(data.error){ addLog(`✗ ${data.error}`,"error"); }
        else{
          addLog(`✓ ${file.name} — ${data.scan_time}s`,"success");
          data.results.forEach(r=>{
            const n=r.vulns?.length||0;
            addLog(`  ${r.protocol}: ${n} vuln${n!==1?"s":""}`, r.risk_score>=61?"warn":"success");
          });
          setResults(prev=>[...prev,{file:file.name,...data}]);
        }
      }catch(e){ addLog(`✗ Network error: ${e.message}`,"error"); }
    }
    addLog("Scan complete.","success");
    setScanning(false);
  };

  const handlePDF=async()=>{
    if(!results.length) return;
    setGenPdf(true);
    addLog("Generating PDF report...","info");
    try{
      await generatePDF(results);
      addLog("✓ PDF saved successfully","success");
    }catch(e){ addLog(`✗ PDF error: ${e.message}`,"error"); }
    setGenPdf(false);
  };

  const handleScanStart = (selected) => {
    setShowModal(false);
    handleScan(selected);
  };

  return (
    <>
      {showModal && (
        <ProtocolModal
          files={files}
          protocols={protocols}
          setProtocols={setProtocols}
          onCancel={()=>setShowModal(false)}
          onScan={handleScanStart}
        />
      )}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        body{background:${C.bg};color:${C.text};font-family:'Syne',sans-serif}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-track{background:${C.surface}}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px}
        @keyframes pulse{0%,100%{opacity:.25;transform:scale(.7)}50%{opacity:1;transform:scale(1)}}
        @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
      `}</style>

      <div style={{minHeight:"100vh",display:"flex",flexDirection:"column"}}>

        {/* Header */}
        <header style={{borderBottom:`1px solid ${C.border}`,padding:"14px 28px",
          display:"flex",justifyContent:"space-between",alignItems:"center",
          background:C.surface,position:"sticky",top:0,zIndex:100}}>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <div style={{width:34,height:34,borderRadius:8,
              background:`linear-gradient(135deg,${C.accent}30,transparent)`,
              border:`1px solid ${C.accent}50`,
              display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>📡</div>
            <div>
              <div style={{fontFamily:"'IBM Plex Mono',monospace",fontWeight:700,
                fontSize:14,color:C.accent,letterSpacing:2}}>SAGE</div>
              <div style={{fontSize:9,color:C.muted,letterSpacing:3}}>NON-IP IOT SCANNER</div>
            </div>
          </div>

          <div style={{display:"flex",alignItems:"center",gap:10}}>
            {/* Nav tabs */}
            {results.length>0 && (
              <div style={{display:"flex",gap:4,background:C.card,
                border:`1px solid ${C.border}`,borderRadius:10,padding:4}}>
                {[
                  {id:"scan",     label:"🔍 Scan"},
                  {id:"stats",    label:"📊 Statistics"},
                  {id:"topology", label:"🕸 Topology"},
                  {id:"attack",   label:"⚔ Attack Chain"},
                ].map(p=>(
                  <button key={p.id} onClick={()=>setPage(p.id)} style={{
                    padding:"5px 14px",borderRadius:7,border:"none",
                    background:page===p.id?`${C.accent}25`:"transparent",
                    color:page===p.id?C.accent:C.muted,
                    fontSize:11,fontWeight:700,letterSpacing:1,
                    cursor:"pointer",transition:"all .2s",
                    fontFamily:"'Syne',sans-serif",
                    textTransform:"uppercase"}}>
                    {p.label}
                  </button>
                ))}
              </div>
            )}

            {/* PDF Button */}
            {results.length>0 && (
              <button onClick={handlePDF} disabled={genPdf} style={{
                display:"flex",alignItems:"center",gap:7,
                padding:"7px 16px",borderRadius:8,
                border:`1px solid ${C.accent}60`,
                background:`linear-gradient(135deg,${C.accent}20,${C.accent}08)`,
                color:genPdf?C.muted:C.accent,fontWeight:700,fontSize:11,letterSpacing:1,
                cursor:genPdf?"not-allowed":"pointer",
                fontFamily:"'Syne',sans-serif",transition:"all .2s"}}>
                <span style={{fontSize:14}}>⬇</span>
                {genPdf?"Generating...":"Export PDF"}
              </button>
            )}

            {/* Backend status */}
            <div style={{display:"flex",alignItems:"center",gap:8,
              background:C.card,border:`1px solid ${C.border}`,
              borderRadius:20,padding:"5px 14px"}}>
              <div style={{width:7,height:7,borderRadius:"50%",
                background:backendOk===null?C.muted:backendOk?C.green:C.red,
                boxShadow:backendOk?`0 0 6px ${C.green}`:"none"}}/>
              <span style={{fontSize:11,color:C.muted,fontFamily:"monospace"}}>
                {backendOk===null?"checking...":backendOk?"backend connected":"backend offline"}
              </span>
            </div>
          </div>
        </header>

        <div style={{display:"flex",flex:1}}>

          {/* Sidebar */}
          <aside style={{width:280,borderRight:`1px solid ${C.border}`,
            background:C.surface,padding:18,display:"flex",
            flexDirection:"column",gap:14,flexShrink:0}}>

            {backendOk===false && (
              <div style={{background:"rgba(255,64,96,0.1)",border:`1px solid ${C.red}40`,
                borderRadius:8,padding:"10px 12px",fontSize:11,color:C.red,lineHeight:1.6}}>
                ⚠ Backend offline<br/>
                <span style={{color:C.muted}}>Run: <code style={{color:C.yellow}}>python app.py</code></span>
              </div>
            )}

            {/* Drop zone */}
            <div onDragOver={e=>{e.preventDefault();setDragging(true)}}
              onDragLeave={()=>setDragging(false)} onDrop={handleDrop}
              onClick={()=>inputRef.current.click()}
              style={{border:`2px dashed ${dragging?C.accent:C.border}`,
                borderRadius:10,padding:"24px 14px",textAlign:"center",
                cursor:"pointer",background:dragging?`${C.accent}08`:"transparent",
                transition:"all .2s"}}>
              <div style={{fontSize:26,marginBottom:6}}>📂</div>
              <div style={{fontSize:12,color:C.text,fontWeight:600,marginBottom:3}}>Drop .pcap / .pcapng</div>
              <div style={{fontSize:10,color:C.muted}}>or click to browse</div>
              <input ref={inputRef} type="file" accept=".pcap,.pcapng" multiple
                style={{display:"none"}}
                onChange={e=>{
                  const chosen=Array.from(e.target.files).filter(f=>f.name.match(/\.(pcap|pcapng)$/i));
                  if(chosen.length){ setFiles(prev=>[...prev,...chosen]); setShowModal(true); }
                }}/>
            </div>

            {/* File list */}
            {files.length>0 && (
              <div style={{display:"flex",flexDirection:"column",gap:5}}>
                <div style={{fontSize:9,color:C.muted,letterSpacing:2}}>QUEUED</div>
                {files.map((f,i)=>(
                  <div key={i} style={{display:"flex",justifyContent:"space-between",
                    alignItems:"center",background:C.card,border:`1px solid ${C.border}`,
                    borderRadius:6,padding:"6px 10px",fontSize:11,animation:"fadeUp .2s ease"}}>
                    <span style={{color:C.text,overflow:"hidden",textOverflow:"ellipsis",
                      whiteSpace:"nowrap",maxWidth:200}}>{f.name}</span>
                    <button onClick={e=>{e.stopPropagation();
                      const removedFile = files[i].name;
                      const newFiles = files.filter((_,idx)=>idx!==i);
                      setFiles(newFiles);
                      if(newFiles.length===0){
                        setResults([]); setLog([]); setPage("scan");
                      } else {
                        // احذف الـ results الخاصة بهذا الملف
                        setResults(prev => prev.filter(r => r.file !== removedFile));
                      }
                    }}
                      style={{background:"none",border:"none",color:C.muted,
                        cursor:"pointer",fontSize:14,padding:"0 2px"}}>×</button>
                  </div>
                ))}
              </div>
            )}

            {/* Scan button */}
            <button onClick={()=>{ if(files.length) setShowModal(true); }}
              disabled={scanning||!files.length||backendOk===false}
              style={{padding:"11px",borderRadius:8,
                border:`1px solid ${files.length&&!scanning&&backendOk?C.accent:C.border}`,
                background:files.length&&!scanning&&backendOk
                  ?`linear-gradient(135deg,${C.accent}25,${C.accent}10)`:C.card,
                color:files.length&&!scanning&&backendOk?C.accent:C.muted,
                fontWeight:700,fontSize:13,letterSpacing:1,
                cursor:files.length&&!scanning&&backendOk?"pointer":"not-allowed",
                transition:"all .2s",display:"flex",alignItems:"center",
                justifyContent:"center",gap:8,fontFamily:"'Syne',sans-serif"}}>
              {scanning?<><Dots/><span>SCANNING</span></>:"▶  RUN SCAN"}
            </button>

            {/* Log */}
            <div ref={logRef} style={{flex:1,minHeight:100,maxHeight:200,overflowY:"auto",
              background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,
              padding:10,fontFamily:"'IBM Plex Mono',monospace",fontSize:10}}>
              {log.length===0
                ?<div style={{color:C.muted}}>// awaiting scan...</div>
                :log.map((l,i)=>(
                  <div key={i} style={{color:l.color,marginBottom:3}}>
                    <span style={{color:C.muted,marginRight:6}}>[{l.time}]</span>{l.msg}
                  </div>
                ))}
            </div>
          </aside>

          {/* Main */}
          <main style={{flex:1,padding:22,overflowY:"auto"}}>
            {page==="topology" && results.length>0 ? (
              <TopologyPage results={results}/>
            ) : page==="stats" && results.length>0 ? (
              <StatisticsPage results={results}/>
            ) : page==="attack" && results.length>0 ? (
              <AttackChainPage results={results}/>
            ) : results.length===0&&!scanning?(
              <div style={{height:"100%",minHeight:400,display:"flex",flexDirection:"column",
                alignItems:"center",justifyContent:"center",gap:14,color:C.muted}}>
                <div style={{fontSize:44,opacity:.2}}>🔍</div>
                <div style={{fontSize:14,fontWeight:600}}>Drop a .pcap file and scan</div>
                <div style={{fontSize:11,maxWidth:300,textAlign:"center",lineHeight:1.7,opacity:.7}}>
                  Supports Zigbee, BLE & Z-Wave — detects unencrypted traffic,
                  replay attacks, weak keys, and more.
                </div>
              </div>
            ):(
              results.map((fr,fi)=>(
                <div key={fi} style={{marginBottom:28,animation:"fadeUp .3s ease"}}>
                  <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:14}}>
                    <div style={{height:1,flex:1,background:C.border}}/>
                    <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:10,
                      color:C.accent,letterSpacing:1}}>{fr.file}</span>
                    <span style={{fontSize:9,color:C.muted}}>{fr.scan_time}s</span>
                    <div style={{height:1,flex:1,background:C.border}}/>
                  </div>
                  {fr.results?.map((r,i)=><ProtocolResult key={i} r={r}/>)}
                </div>
              ))
            )}
          </main>
        </div>
      </div>
    </>
  );
}