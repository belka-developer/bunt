// Поднимает версию во всех местах сразу: npm run bump -- 0.1.1
import { readFileSync, writeFileSync } from 'node:fs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  console.error('Использование: npm run bump -- 0.1.1');
  process.exit(1);
}

function patch(path, pattern, replacement) {
  const text = readFileSync(path, 'utf8');
  if (!pattern.test(text)) {
    console.error(`Не нашёл версию в ${path}`);
    process.exit(1);
  }
  writeFileSync(path, text.replace(pattern, replacement));
}

patch('src-tauri/tauri.conf.json', /("version":\s*")[^"]+(")/, `$1${version}$2`);
patch('src-tauri/Cargo.toml', /^version = ".*"$/m, `version = "${version}"`);
patch('package.json', /("version":\s*")[^"]+(")/, `$1${version}$2`);

console.log(`Версия ${version} записана в tauri.conf.json, Cargo.toml и package.json.`);
console.log('Дальше:');
console.log(`  git commit -am "v${version}"`);
console.log(`  git tag v${version}`);
console.log('  git push && git push --tags');
