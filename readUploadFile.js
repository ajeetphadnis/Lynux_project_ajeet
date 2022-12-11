fs =  require("fs");



function getUploadFileName(dir, strtStr, endStr) {
		//const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr)) {
				console.log(file);
				return file;
			}	  
		}
	};
exports.getUploadFileName = getUploadFileName;