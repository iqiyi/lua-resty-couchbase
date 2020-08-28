local cjson = require "cjson"
local couchbase = require "resty.couchbase"

local function get_from_service()
    -- nothing
    return "{}"
end

local conf = {
    hosts = { "10.10.10.1:8091", "10.10.10.2:8091"},
    bucket_name = "test",
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
local values, bluk_err = client:get_bluk(key, key1)
if not bluk_err then
    ngx.say(cjson.encode(values))
end

-- test n1ql
local result, query_err = client:query('SELECT country FROM `travel-sample` WHERE name = "Excel Airways";')
ngx.say(cjson.encode(err))
if not query_err then
    ngx.say(result)
end

-- test get get_from_replica
local value, get_err = client:get(key)
if value then
    ngx.say(value)
else
    if get_err then
        if string.find(get_err, "Not found") then
            ngx.log(ngx.INFO, "key not found: ", key, " error: ", get_err)
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