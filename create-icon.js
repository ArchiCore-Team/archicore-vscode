const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (const byte of buf) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])));
  return Buffer.concat([lenBuf, typeBytes, data, crcBuf]);
}

const W = 128, H = 128;
const BG = [15, 23, 42];   // #0f172a
const FG = [56, 189, 248]; // #38bdf8

// Draw pixels
const rawData = [];
for (let y = 0; y < H; y++) {
  rawData.push(0x00); // filter byte
  for (let x = 0; x < W; x++) {
    const cx = x - 64, cy = y - 64;
    const r2 = cx * cx + cy * cy;
    // Shield / arc shape: outer ring r=50, inner r=36, cut bottom half open
    const outer = r2 < 50 * 50;
    const inner = r2 < 36 * 36;
    const ring = outer && !inner;
    // Top arc: only draw ring in upper portion + sides
    const isArc = ring && (cy < 10 || Math.abs(cx) > 20);
    // "A" crossbar: horizontal bar at y ~ center
    const crossbar = cy >= -2 && cy <= 2 && Math.abs(cx) < 24 && Math.abs(cx) > 4;
    // "A" legs: two diagonal lines forming an A
    const leftLeg = cx >= -30 && cx <= -20 && cy >= -20 && cy <= 40;
    const rightLeg = cx >= 20 && cx <= 30 && cy >= -20 && cy <= 40;
    // Peak of A
    const peak = cy >= -44 && cy <= -20 && Math.abs(cx) <= (-cy - 20) * 0.6 + 5 && Math.abs(cx) >= (-cy - 20) * 0.3;

    const draw = isArc || crossbar || leftLeg || rightLeg || peak;
    const color = draw ? FG : BG;
    rawData.push(color[0], color[1], color[2]);
  }
}

const compressed = zlib.deflateSync(Buffer.from(rawData));

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8;  // bit depth
ihdr[9] = 2;  // color type RGB
ihdr[10] = 0; // compression
ihdr[11] = 0; // filter
ihdr[12] = 0; // interlace

const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), // PNG signature
  chunk('IHDR', ihdr),
  chunk('IDAT', compressed),
  chunk('IEND', Buffer.alloc(0)),
]);

const outPath = path.join(__dirname, 'assets', 'icon.png');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, png);
console.log(`icon.png created (${png.length} bytes) at ${outPath}`);
