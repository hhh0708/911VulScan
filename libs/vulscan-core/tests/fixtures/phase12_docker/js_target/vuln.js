function vulnerable(payload) {
  const marker = (payload && payload.marker) || "ORACLE_HIT";
  console.log(marker);
  return marker;
}

module.exports = { vulnerable };
