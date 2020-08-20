Name
====

lua-resty-couchbase - Lua couchbase client driver for the ngx_lua based on the cosocket API.

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Debugging](#debugging)
* [Automatic Error Logging](#automatic-error-logging)
* [Check List for Issues](#check-list-for-issues)
* [Limitations](#limitations)
* [Installation](#installation)
* [TODO](#todo)
* [Bugs and Patches](#bugs-and-patches)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

This library is considered production ready.

Description
===========

This Lua library is a CouchBase client driver for the ngx_lua nginx module:

https://github.com/openresty/lua-nginx-module/#readme

This Lua library takes advantage of ngx_lua's cosocket API, which ensures
100% nonblocking behavior.

Note that at least [ngx_lua 0.5.14](https://github.com/chaoslawful/lua-nginx-module/tags) or [OpenResty 1.2.1.14](http://openresty.org/#Download) is required.

Synopsis
========

```lua
    lua_package_path "/path/to/lua-resty-couchbase/lib/?.lua;;";

    server {
        location /test {
            content_by_lua_block {
                local cjson = require "cjson"
                local couchbase = require "resty.couchbase"

                local function get_from_service()
                    -- nothing
                    return "{}"
                end

                local conf = {
                    hosts = { "10.10.8.96:8091", "10.10.8.97:8091"},
                    buket_name = "test",
                    bucketpwd = "test-password",
                }

                local client, err = couchbase:create_client(conf.hosts, conf.bucket_name, conf.bucketpwd)
                if client == nil then
                    ngx.log(ngx.ERR, err)
                end

                -- test set_timeout
                client:set_timeout(500)

                local key = "test-key"
                local key1 = "test-key1"
                -- test set
                client:set(key, "{}")
                client:set(key1, "{}")

                -- test get_bluk
                local values, err = client:get_bluk({key, key1})
                if not err then
                    ngx.say(cjson.encode(values))
                end

                -- test n1ql
                local result, err = client:query('SELECT country FROM `travel-sample` WHERE name = "Excel Airways";')
                if not err then
                    ngx.say(result)
                end

                -- test get get_from_replica
                local value, err = client:get(key)
                if value then
                    ngx.say(value)
                else
                    if err then
                        if string.find(err, "Not found") then
                            ngx.log(ngx.INFO, "key not found: ", key, " error: ", err)
                            ngx.say(get_from_service())
                        else
                            local value_bak, err_bak = client:get_from_replica(key)
                            if value_bak then
                                ngx.log(ngx.WARN, "get key from replica success: ", key)
                                ngx.say(value_bak)
                            else
                                ngx.log(ngx.ERR, "get replica error: ", key, "error: ", err_bak)
                                ngx.say(get_from_service())
                            end
                        end
                    end
                end

                -- test close
                client:close()

            }
        }
    }
```

[Back to TOC](#table-of-contents)

Debugging
=========

It is usually convenient to use the [lua-cjson](http://www.kyne.com.au/~mark/software/lua-cjson.php) library to encode the return values of the couchbase command methods to JSON. For example,

```lua
    local cjson = require "cjson"
    ...
    local res, err = client:get("h1234")
    if res then
        print("res: ", cjson.encode(res))
    end
```

[Back to TOC](#table-of-contents)

Automatic Error Logging
=======================

By default the underlying [ngx_lua](https://github.com/openresty/lua-nginx-module/#readme) module
does error logging when socket errors happen. If you are already doing proper error
handling in your own Lua code, then you are recommended to disable this automatic error logging by turning off [ngx_lua](https://github.com/openresty/lua-nginx-module/#readme)'s [lua_socket_log_errors](https://github.com/openresty/lua-nginx-module/#lua_socket_log_errors) directive, that is,

```nginx
    lua_socket_log_errors off;
```

[Back to TOC](#table-of-contents)

Check List for Issues
=====================

1. Ensure you configure the connection pool size properly in the [set_keepalive](#set_keepalive) . Basically if your NGINX handle `n` concurrent requests and your NGINX has `m` workers, then the connection pool size should be configured as `n/m`. For example, if your NGINX usually handles 1000 concurrent requests and you have 10 NGINX workers, then the connection pool size should be 100.
2. Ensure you are not using too short timeout setting in the [set_timeout](#set_timeout) or [set_timeouts](#set_timeouts) methods. If you have to, try redoing the operation upon timeout and turning off [automatic error logging](#automatic-error-logging) (because you are already doing proper error handling in your own Lua code).
3. If your NGINX worker processes' CPU usage is very high under load, then the NGINX event loop might be blocked by the CPU computation too much. Try sampling a [C-land on-CPU Flame Graph](https://github.com/agentzh/nginx-systemtap-toolkit#sample-bt) and [Lua-land on-CPU Flame Graph](https://github.com/agentzh/stapxx#ngx-lj-lua-stacks) for a typical NGINX worker process. You can optimize the CPU-bound things according to these Flame Graphs.
4. If your NGINX worker processes' CPU usage is very low under load, then the NGINX event loop might be blocked by some blocking system calls (like file IO system calls). You can confirm the issue by running the [epoll-loop-blocking-distr](https://github.com/agentzh/stapxx#epoll-loop-blocking-distr) tool against a typical NGINX worker process. If it is indeed the case, then you can further sample a [C-land off-CPU Flame Graph](https://github.com/agentzh/nginx-systemtap-toolkit#sample-bt-off-cpu) for a NGINX worker process to analyze the actual blockers.

[Back to TOC](#table-of-contents)

Limitations
===========

* This library cannot be used in code contexts like init_by_lua*, set_by_lua*, log_by_lua*, and
header_filter_by_lua* where the ngx_lua cosocket API is not available.

[Back to TOC](#table-of-contents)

TODO
====

[Back to TOC](#table-of-contents)

Bugs and Patches
================

Please report bugs or submit patches by

1. creating a ticket on the gitlab. 

[Back to TOC](#table-of-contents)

Author
======

goecho <hyphen9@foxmail.com>

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========
* the ngx_lua module: https://github.com/openresty/lua-nginx-module/#readme

[Back to TOC](#table-of-contents)
