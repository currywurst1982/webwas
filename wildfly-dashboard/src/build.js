'use strict';

// Build identifier shared by the server and the page (public/js/app.js BUILD and the
// dashboard-build meta in public/app.html must carry the same value; a test checks it).
// Lets the page tell when the files were updated but the server process was not restarted.
module.exports = { BUILD: '2026.10.06.3' };
