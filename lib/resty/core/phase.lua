-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require 'ffi'
local base = require "resty.core.base"


local C = ffi.C
local ffi_str = ffi.string
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local getfenv = getfenv
local error = error


ffi.cdef [[
int ngx_http_lua_ffi_get_phase(ngx_http_request_t *r, char *buf, size_t *len)
]]


function ngx.get_phase()
    local r = getfenv(0).__ngx_req

    local buf = get_string_buf(32)
    local sizep = get_size_ptr()
    local rc = C.ngx_http_lua_ffi_get_phase(r, buf, sizep)
    if rc == base.FFI_OK then
        return ffi_str(buf, sizep[0])
    elseif rc == base.FFI_NO_REQ_CTX then
        return error("no request ctx found")
    end
end


return {
    version = base.version
}
