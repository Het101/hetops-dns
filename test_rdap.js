async function testRDAP() {
  try {
    const res = await fetch('https://rdap.org/domain/wizlo.com');
    const data = await res.json();
    console.log(JSON.stringify(data).substring(0, 1000));
  } catch (err) {
    console.error(err);
  }
}
testRDAP();
