'use strict';

const { runScenario, scenarios } = require('./rollout.cjs');

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !scenarios.includes(args[0])) {
    console.error('Kullanım: node phase2/demo.cjs ' + scenarios.join('|'));
    process.exitCode = 1;
    return;
  }
  const report = await runScenario(args[0]);
  console.log(JSON.stringify(report));
  process.exitCode = report.exitCode;
}

main().catch(error => {
  console.error(JSON.stringify({ outcome: 'stopped', operatorRequired: true, reason: error.code || 'INTERNAL_ERROR' }));
  process.exitCode = 1;
});
