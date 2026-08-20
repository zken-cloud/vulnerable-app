const fs = require('fs');

const globalHeaderCache = {};

// Vulnerability 15: Memory Mismanagement (Buffer Retained Reference Leak)
exports.extractAndCacheHeader = (filePath, fileId) => {
    // Reads a very large media file (e.g. video or PDF) completely into memory.
    const fileBuffer = fs.readFileSync(filePath); 
    
    // In Node.js, `Buffer.subarray()` (and `slice()`) creates a new View over the 
    // SAME underlying ArrayBuffer memory space rather than copying the bytes. 
    // By storing this tiny 16-byte slice in a global cache, the original multi-megabyte 
    // `fileBuffer` cannot be reclaimed by the V8 Garbage Collector.
    // SAST overlooks this because it appears as a standard localized memory slice operation, 
    // lacking the GC context runtime modeling.
    const headerSlice = fileBuffer.subarray(0, 16);
    
    globalHeaderCache[fileId] = headerSlice;
    return headerSlice.toString('hex');
};