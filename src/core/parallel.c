#include "transfer.h"
#include <sys/stat.h>

int sx_transfer_send_parallel(const char *host, uint16_t port, const char *path, uint32_t streams){
	if(streams <= 1) return sx_transfer_send(host, port, path);
	struct stat st; if(stat(path,&st)!=0) return -1; uint64_t size = (uint64_t)st.st_size;
	uint64_t chunk = size / streams; if(chunk == 0) chunk = size;
	int rc = 0;
	for(uint32_t i=0;i<streams;i++){
		uint64_t off = i * chunk;
		uint64_t end = (i+1==streams) ? size : (off + chunk);
		uint64_t len = (end>off)?(end-off):0;
		if(len == 0) continue;
		rc = sx_transfer_send_offset(host, port, path, off);
		if(rc != 0) return rc;
	}
	return rc;
}