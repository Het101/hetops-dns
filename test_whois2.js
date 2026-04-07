const whois = require('whois');

whois.lookup('wizlo.com', { follow: 1 }, (err, data) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log("RAW LENGTH:", data.length);
  console.log("FIRST 200 CHARS:");
  console.log(JSON.stringify(data.substring(0, 200)));
  
  function parseWhois(raw){
    const o={};
    for(const line of raw.split('\n')){
      const m=line.match(/^([^:%]+):\s*(.+)$/); if(!m) continue;
      const k=m[1].trim().toLowerCase(), v=m[2].trim();
      if(!v||v.includes('REDACTED')||v.startsWith('http')) continue;
      if(o[k]){
        if(!Array.isArray(o[k])) o[k]=[o[k]];
        if(!o[k].includes(v)) o[k].push(v);
      } else {
        o[k]=v;
      }
    }
    return o;
  }
  
  const parsed = parseWhois(data);
  console.log("PARSED KEYS:", Object.keys(parsed));
});
