const fs = require('fs');
const path = require('path');

// Directory to watch - adjust as needed
const watchDir = process.argv[2] || './client/c01_client-first-app';

console.log(`?? Watching for file changes in: ${watchDir}`);
console.log(`Starting at: ${new Date().toISOString()}\n`);

fs.watch(watchDir, { recursive: true }, (eventType, filename) => {
  if (filename) {
    const timestamp = new Date().toISOString();
    const fullPath = path.join(watchDir, filename);

    try {
      const stats = fs.statSync(fullPath);
      console.log(`[${timestamp}]`);
      console.log(`  Event: ${eventType}`);
      console.log(`  File: ${filename}`);
      console.log(`  Size: ${stats.size} bytes`);
      console.log(`  Modified: ${stats.mtime.toISOString()}`);
      console.log('');
    } catch (err) {
      console.log(`[${timestamp}] ${eventType}: ${filename} (deleted or temp)`);
    }
  }
});