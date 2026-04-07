const raw = `Domain Name: wizlo.com
Registry Domain ID: 1326870666_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com
Updated Date: 2025-09-16T23:21:58Z
Creation Date: 2007-11-08T12:35:59Z
Registrar Registration Expiration Date: 2026-11-08T12:35:59Z
Registrar: GoDaddy.com, LLC
Registrar IANA ID: 146
Registrar Abuse Contact Email: abuse@godaddy.com
Registrar Abuse Contact Phone: +1.4806242505
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Country: US
Name Server: NS58.DOMAINCONTROL.COM
DNSSEC: unsigned`;

function parseWhois(raw){
  const o={};
  for(const line of raw.split('\n')){
    const m=line.match(/^\s*([^:%>\n]+):\s*(.*)$/); if(!m) continue;
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

const p = parseWhois(raw);
console.log("Parsed keys:", Object.keys(p));

const FIELDS=[
  ['Domain Name','domain name'],['Registrar','registrar'],['IANA ID','registrar iana id'],
  ['Registered','creation date'],['Expires','registry expiry date'],['Updated','updated date'],
  ['Status','domain status'],['Name Servers','name server'],['DNSSEC','dnssec'],
  ['Registrant Org','registrant organization'],['Country','registrant country'],
  ['Abuse Email','registrar abuse contact email'],
];

let found = 0;
FIELDS.forEach(([label,key]) => {
  if (p[key]) found++;
});
console.log("Found matching fields:", found);
