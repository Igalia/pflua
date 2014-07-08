module(...,package.seeall)

local ffi = require("ffi")
local types = require("pf.types") -- Load FFI declarations.

ffi.cdef[[
int open(const char *pathname, int flags);
typedef long int off_t;
off_t lseek(int fd, off_t offset, int whence);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
]]

function open(filename)
   return ffi.C.open(filename, 0)
end

function mmap(fd, size)
   -- mmap(0, stat_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)
   return ffi.C.mmap(ffi.cast("void *", 0), size, 1, 2, fd, 0)
end

function size(fd)
   -- size = lseek(fd, 0, SEEK_END)
   local size = ffi.C.lseek(fd, 0, 2)
   -- repos the file pointer
   ffi.C.lseek(fd, 0, 0)
   return size
end
