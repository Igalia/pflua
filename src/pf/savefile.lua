module(...,package.seeall)

local ffi = require("ffi")
local types = require("pf.types")

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
   local PROT_READ = 1
   local MAP_PRIVATE = 2
   return ffi.C.mmap(ffi.cast("void *", 0), size, PROT_READ, MAP_PRIVATE, fd, 0)
end

function size(fd)
   local SEEK_SET = 0
   local SEEK_END = 2
   local size = ffi.C.lseek(fd, 0, SEEK_END)
   ffi.C.lseek(fd, 0, SEEK_SET)
   return size
end

function records_mm(filename)
   local fd = open(filename, O_RDONLY)
   if fd == -1 then
      error("Error opening " .. filename)
   end
   local size = size(fd)
   local ptr = mmap(fd, size)
   if ptr == ffi.cast("void *", -1) then
      error("Error mmapping " .. filename)
   end
   ptr = ffi.cast("unsigned char *", ptr)
   local ptr_end = ptr + size
   local header = ffi.cast("struct pcap_file *", ptr)
   if header.magic_number == 0xD4C3B2A1 then
      error("Endian mismatch in " .. filename)
   elseif header.magic_number ~= 0xA1B2C3D4 then
      error("Bad PCAP magic number in " .. filename)
   end
   ptr = ptr + ffi.sizeof("struct pcap_file")
   local function pcap_records_it()
      local record = ffi.cast("struct pcap_record *", ptr)
      if ptr >= ptr_end then return nil end
      local datalen = math.min(record.orig_len, record.incl_len)
      local packet = ffi.cast("unsigned char *", record + 1)
      ptr = packet + datalen
      local extra = nil
      if record.incl_len == datalen + ffi.sizeof("struct pcap_record_extra") then
	 extra = ffi.cast("struct pcap_record_extra *", ptr)
	 ptr = ptr + ffi.sizeof("struct pcap_record_extra")
      end
      return packet, record, extra
   end
   return pcap_records_it, true, true
end

function write_file_header(file)
   local pcap_file = ffi.new("struct pcap_file")
   pcap_file.magic_number = 0xa1b2c3d4
   pcap_file.version_major = 2
   pcap_file.version_minor = 4
   pcap_file.snaplen = 65535
   pcap_file.network = 1
   file:write(ffi.string(pcap_file, ffi.sizeof(pcap_file)))
   file:flush()
end

local pcap_extra = ffi.new("struct pcap_record_extra")
ffi.fill(pcap_extra, ffi.sizeof(pcap_extra), 0)

function write_record (file, ffi_buffer, length)
   write_record_header(file, length)
   file:write(ffi.string(ffi_buffer, length))
   file:flush()
end

function write_record_header (file, length)
   local pcap_record = ffi.new("struct pcap_record")
   pcap_record.incl_len = length
   pcap_record.orig_len = length
   file:write(ffi.string(pcap_record, ffi.sizeof(pcap_record)))
end

-- Return an iterator for pcap records in FILENAME.
function records (filename)
   local file = io.open(filename, "r")
   if file == nil then error("Unable to open file: " .. filename) end
   local pcap_file = readc(file, "struct pcap_file")
   if pcap_file.magic_number == 0xD4C3B2A1 then
      error("Endian mismatch in " .. filename)
   elseif pcap_file.magic_number ~= 0xA1B2C3D4 then
      error("Bad PCAP magic number in " .. filename)
   end
   local function pcap_records_it (t, i)
      local record = readc(file, "struct pcap_record")
      if record == nil then return nil end
      local datalen = math.min(record.orig_len, record.incl_len)
      local packet = file:read(datalen)
      local extra = nil
      if record.incl_len == #packet + ffi.sizeof("struct pcap_record_extra") then
	 extra = readc(file, "struct pcap_record_extra")
      end
      return packet, record, extra
   end
   return pcap_records_it, true, true
end

-- Read a C object of TYPE from FILE. Return a pointer to the result.
function readc(file, type)
   local string = file:read(ffi.sizeof(type))
   if string == nil then return nil end
   if #string ~= ffi.sizeof(type) then
      error("short read of " .. type .. " from " .. tostring(file))
   end
   return ffi.cast(type.."*", string)
end
