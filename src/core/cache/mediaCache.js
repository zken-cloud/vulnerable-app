const fs = require('fs');

const globalHeaderCache = {};

exports.extractAndCacheHeader = (filePath, fileId) => {
    const fileBuffer = fs.readFileSync(filePath); 
    
    const headerSlice = fileBuffer.subarray(0, 16);
    
    globalHeaderCache[fileId] = headerSlice;
    return headerSlice.toString('hex');
};