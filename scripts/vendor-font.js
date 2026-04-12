#!/usr/bin/env node
'use strict';

/**
 * vendor-font.js — Download a Google Font and vendor it locally.
 *
 * Usage:
 *   node scripts/vendor-font.js "Plus Jakarta Sans" 200,300,400,500,600,700,800
 *   node scripts/vendor-font.js "Inter" 400,500,600,700
 *   node scripts/vendor-font.js "JetBrains Mono" 300,400,500,700
 *
 * What it does:
 *   1. Fetches the Google Fonts CSS with a Chrome UA (gets woff2 URLs)
 *   2. Downloads each woff2 file to public/fonts/
 *   3. Generates public/fonts/font.css with local @font-face rules
 *   4. Prints the <link> tag to add to head.html
 *
 * After running:
 *   - Replace the Google Fonts <link> in views/partials/head.html with:
 *       <link rel="stylesheet" href="/fonts/font.css">
 *   - Remove https://fonts.googleapis.com from style-src CSP
 *   - Remove https://fonts.gstatic.com from font-src CSP
 */

var https = require('https');
var fs = require('fs');
var path = require('path');

var FONTS_DIR = path.join(__dirname, '..', 'public', 'fonts');

// Chrome UA to get woff2 format from Google Fonts
var CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function fetch(url) {
  return new Promise(function (resolve, reject) {
    var opts = { headers: { 'User-Agent': CHROME_UA } };
    https.get(url, opts, function (res) {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location).then(resolve, reject);
      }
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () { resolve(Buffer.concat(chunks)); });
      res.on('error', reject);
    }).on('error', reject);
  });
}

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

async function main() {
  var fontName = process.argv[2];
  var weights = process.argv[3];

  if (!fontName) {
    console.log('Usage: node scripts/vendor-font.js "Font Name" 200,300,400,500,600,700,800');
    console.log('');
    console.log('Examples:');
    console.log('  node scripts/vendor-font.js "Plus Jakarta Sans" 200,300,400,500,600,700,800');
    console.log('  node scripts/vendor-font.js "Inter" 400,500,600,700');
    console.log('  node scripts/vendor-font.js "JetBrains Mono" 300,400,500,700');
    process.exit(1);
  }

  if (!weights) {
    weights = '200,300,400,500,600,700,800';
    console.log('No weights specified, using default: ' + weights);
  }

  var fontSlug = slugify(fontName);
  var fontParam = fontName.replace(/ /g, '+');
  var weightParam = weights.split(',').map(function (w) { return w.trim(); }).join(';');
  var cssUrl = 'https://fonts.googleapis.com/css2?family=' + fontParam + ':wght@' + weightParam + '&display=swap';

  console.log('');
  console.log('Vendoring: ' + fontName);
  console.log('Weights:   ' + weights);
  console.log('CSS URL:   ' + cssUrl);
  console.log('');

  // Fetch the CSS
  console.log('Fetching Google Fonts CSS...');
  var css = (await fetch(cssUrl)).toString('utf8');

  if (!css.includes('@font-face')) {
    console.error('ERROR: No @font-face rules found. Check font name and weights.');
    console.error('Response:', css.substring(0, 500));
    process.exit(1);
  }

  // Create fonts directory
  fs.mkdirSync(FONTS_DIR, { recursive: true });

  // Parse all woff2 URLs and download them
  var urlPattern = /url\((https:\/\/fonts\.gstatic\.com\/[^)]+\.woff2)\)/g;
  var match;
  var downloads = [];
  var urlMap = {};

  while ((match = urlPattern.exec(css)) !== null) {
    var url = match[1];
    if (!urlMap[url]) {
      downloads.push(url);
      urlMap[url] = true;
    }
  }

  if (downloads.length === 0) {
    console.error('ERROR: No woff2 URLs found in CSS. Got format:');
    console.error(css.substring(0, 500));
    process.exit(1);
  }

  console.log('Found ' + downloads.length + ' font files to download');

  var totalBytes = 0;
  for (var i = 0; i < downloads.length; i++) {
    var dl = downloads[i];
    var filename = fontSlug + '-' + path.basename(dl);
    var destPath = path.join(FONTS_DIR, filename);

    process.stdout.write('  ' + (i + 1) + '/' + downloads.length + ' ' + filename + '... ');
    var data = await fetch(dl);
    fs.writeFileSync(destPath, data);
    totalBytes += data.length;
    console.log((data.length / 1024).toFixed(1) + ' KB');

    // Rewrite URL in CSS
    css = css.split(dl).join('/fonts/' + filename);
  }

  // Write local CSS
  var cssPath = path.join(FONTS_DIR, 'font.css');
  fs.writeFileSync(cssPath, css, 'utf8');

  var faceCount = (css.match(/@font-face/g) || []).length;

  console.log('');
  console.log('Done!');
  console.log('  Font files: ' + downloads.length + ' (' + (totalBytes / 1024).toFixed(0) + ' KB total)');
  console.log('  @font-face: ' + faceCount + ' rules');
  console.log('  CSS:        public/fonts/font.css');
  console.log('');
  console.log('Next steps:');
  console.log('  1. In views/partials/head.html, replace:');
  console.log('       <link rel="preconnect" href="https://fonts.googleapis.com">');
  console.log('       <link href="https://fonts.googleapis.com/css2?family=..." rel="stylesheet">');
  console.log('     with:');
  console.log('       <link rel="stylesheet" href="/fonts/font.css">');
  console.log('');
  console.log('  2. In middleware/security-headers.js, remove from CSP:');
  console.log('       style-src: https://fonts.googleapis.com');
  console.log('       font-src:  https://fonts.gstatic.com');
  console.log('');
  console.log('  To change fonts later, just run this script again with a different font name.');
}

main().catch(function (err) {
  console.error('FATAL:', err.message);
  process.exit(1);
});
