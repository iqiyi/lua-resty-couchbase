--
-- Lua couchbase client driver for the ngx_lua based on the cosocket API.
--
-- Copyright (C) 2020 iQIYI (www.iqiyi.com).
-- All Rights Reserved.
--

local bit = require "bit"
local cjson = require 'cjson'
local unpack = unpack

local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift
local bor = bit.bor
local bxor = bit.bxor
local tohex = bit.tohex
local random = math.random
local min = math.min
local strbyte = string.byte
local strchar = string.char
local strlen = string.len
local table_concat = table.concat

local ngx_crc32 = ngx.crc32_short
local ngx_md5 = ngx.md5
local ngx_md5_bin = ngx.md5_bin
local ngx_gsub = ngx.re.gsub
local ngx_encode_args = ngx.encode_args
local tcp = ngx.socket.tcp
local ldict = ngx.shared.ldict
local base64 = ngx.encode_base64

local _M = { _VERSION = '0.3' }
local mt = { __index = _M }
local vbuckets = {}

local max_tries = 3
local default_timeout = 5000
local pool_max_idle_timeout = 10000
local pool_size = 100

local function log_info(...)
    ngx.log(ngx.INFO, ...)
end

local function log_error(...)
    ngx.log(ngx.ERR, ...)
end

local function host2server(host_ports, need_random)

    local servers = {}
    for _, host_port in ipairs(host_ports) do
        local host = ngx_gsub(host_port, ':[0-9]+', '')
        local port = ngx_gsub(host_port, '[^:]+:', '')
        table.insert(servers, { host = host, port = tonumber(port), t = random(1, 100), name = host_port })
    end

    if need_random then
        table.sort(servers, function(a, b)
            return a.t > b.t
        end)
    end

    return servers
end

local function http_request(host, port, url, token)
    local sock, err = tcp()
    if not sock then
        return nil, err
    end
    sock:settimeout(default_timeout)

    local ok, connect_err = sock:connect(host, port)
    if not ok then
        return nil, connect_err
    end

    -- Only simple http 1.0 request. Not support the gzip and chunked.
    local request = {}
    request[#request + 1] = 'GET ' .. url .. ' HTTP/1.0\r\n'
    request[#request + 1] = 'User-Agent: lua-couchbase-client v0.1\r\n'
    request[#request + 1] = 'Authorization: Basic ' .. token .. '\r\n'
    request[#request + 1] = 'Accept: */*\r\n'
    request[#request + 1] = '\r\n'
    local bytes, send_err = sock:send(table_concat(request))
    if not bytes then
        return nil, send_err
    end

    local length = 0
    while true do
        local header, header_err = sock:receive('*l')
        if not header then
            return nil, header_err
        end
        if string.find(header, 'Content%-Length:') then
            length = string.gsub(header, 'Content%-Length:', '')
        end
        if not header or header == '' then
            break
        end
    end

    local body, body_err
    if tonumber(length) == 0 then
        body, body_err = sock:receive('*a')
    else
        body, body_err = sock:receive(tonumber(length))
    end
    if not body then
        return nil, body_err
    end

    return body
end

local function fetch_configs(servers, buck_name, password)
    local configs = {}
    local token
    if password == nil then
        password = ''
    end
    token = base64(buck_name .. ':' .. password)
    local tries = min(max_tries, #servers)
    for try = 1, tries, 1 do
        local server = servers[try]

        log_info('try to fetch config ,from host=', server.host, ',port=', server.port, "token=", token)

        local body, err = http_request(server.host, server.port, '/pools/default/buckets/' .. buck_name, token)
        if body then
            -- bug fixed with body is 'Requested resource not found.'.
            if string.find(body, '^{') then
                local config = cjson.decode(body)
                configs[#configs + 1] = config
                break
            else
                log_error(string.format(
                    'fetch config is error,from host=%s, port=%s, buck_name=%s, token=%s, server response body=%s',
                        server.host, server.port, buck_name, token, body))
            end
        else
            log_error(string.format('fetch config is error,from host=%s, port=%s, buck_name=%s, token=%s, err=%s',
                    server.host, server.port, buck_name, token, err))
        end
    end

    return configs
end

local function create_vbucket(host_ports, buck_name, password)
    local servers = host2server(host_ports, true)
    local vbucket = {
        host_ports = host_ports,
        servers = servers,
        name = buck_name,
        password = password,
        type = 'membase',
        hash = 'CRC',
        mast = -1,
        nodes = {},
        vmap = {},
    }

    local configs = fetch_configs(servers, buck_name, password)
    if #configs == 0 then
        return nil, 'fail to fetch configs.'
    end

    for _, config in ipairs(configs) do
        if config.name == buck_name then
            if config['bucketType'] == 'membase' then
                local bucket = config['vBucketServerMap']
                if bucket then
                    vbucket.hash = bucket['hashAlgorithm']
                    vbucket.nodes = host2server(bucket['serverList'])
                    local bucket_map = bucket['vBucketMap']
                    vbucket.mast = #bucket_map - 1
                    local vmap = vbucket.vmap
                    local nodes = vbucket.nodes
                    for _, map in ipairs(bucket_map) do
                        local master = map[1]
                        local replica = map[2]
                        table.insert(vmap, { nodes[master + 1], nodes[replica + 1] })
                    end
                end
            elseif config['bucketType'] == 'memcached' then
                local node_servers = {}
                for node in ipairs(config['nodes']) do
                    local node_server = string.gsub(node['hostname'], ':[0-9]+', node['ports'].direct)
                    node_servers[#node_servers + 1] = node_server
                end
                -- Tt's can be ngx_memcached_module.
                return nil, 'Not support the bucketType of memcached!'
            end
        end
    end

    return vbucket
end

local last_reload = 0
local function reload_vbucket(old_vbucket)
    -- reload time 15 seconds.
    if ngx.now() - last_reload > 15 then
        last_reload = ngx.now()
        log_error('try to refresh couchbase conifg.')
        local new_vbucket = create_vbucket(old_vbucket.host_ports, old_vbucket.name, old_vbucket.password)

        if new_vbucket then
            old_vbucket.mast = new_vbucket.mast
            old_vbucket.nodes = new_vbucket.nodes
            old_vbucket.vmap = new_vbucket.vmap
            old_vbucket.sock = new_vbucket.sock
        end
    end
end

local function location_server(vbucket, packet)
    local vbucket_mast = vbucket.mast
    if vbucket_mast == -1 then
        return nil
    end

    local hash = ngx_crc32(packet.key)
    local node_index = band(band(rshift(hash, 16), 0x7fff), vbucket_mast)
    packet.vbucket_id = node_index

    return packet.is_replica and vbucket.vmap[node_index + 1][2] or vbucket.vmap[node_index + 1][1]
end

-- Not used this method.
local function ketama_hash(key)
    local bytes = ngx_md5_bin(key)
    return band(bor(lshift(bytes[4], 24), lshift(bytes[3], 16), lshift(bytes[2], 8), bytes[1]), 0xFFFFFFFF)
end

_M._unused_f1 = ketama_hash

local function byte2str(byte)
    return strchar(unpack(byte))
end

local function hmac(k, c)
    local k_opad = {}
    local k_ipad = {}

    if k then
        if strlen(k) > 64 then
            k = ngx_md5_bin(k)
        end
        for i = 1, strlen(k), 1 do
            k_opad[i] = strbyte(k, i)
            k_ipad[i] = strbyte(k, i)
        end
    end

    for i = 1, 64, 1 do
        k_opad[i] = bxor(k_opad[i] or 0x0, 0x5c)
        k_ipad[i] = bxor(k_ipad[i] or 0x0, 0x36)
    end
    k_opad = byte2str(k_opad)
    k_ipad = byte2str(k_ipad)

    -- hash(k_opad || hash(k_ipad,c))
    return ngx_md5(k_opad .. ngx_md5_bin(k_ipad .. c))
end

local function get_byte2(data, i)
    local a, b = strbyte(data, i, i + 1)
    return bor(lshift(a, 8), b), i + 2
end

local function get_byte4(data, i)
    local a, b, c, d = strbyte(data, i, i + 3)
    return bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d), i + 4
end

local function get_byte8(data, i)
    local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)
    local hi = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
    local lo = bor(lshift(e, 24), lshift(f, 16), lshift(g, 8), h)
    return hi * 4294967296 + lo, i + 8
end

local function pad_zores(bytes, n)
    for _ = 1, n, 1 do
        bytes[#bytes + 1] = 0x00
    end
end

local function set_byte(bytes, n)
    bytes[#bytes + 1] = band(n, 0xff)
end

local function set_byte2(bytes, n)
    if n == 0x00 then
        pad_zores(bytes, n)
    end
    bytes[#bytes + 1] = band(rshift(n, 8), 0xff)
    bytes[#bytes + 1] = band(n, 0xff)
end

local function set_byte4(bytes, n)
    if n == 0x00 then
        pad_zores(bytes, n)
    end
    bytes[#bytes + 1] = band(rshift(n, 24), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 16), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 8), 0xff)
    bytes[#bytes + 1] = band(n, 0xff)
end

local function set_byte8(bytes, n)
    if n == 0x00 then
        pad_zores(bytes, n)
    end
    bytes[#bytes + 1] = band(rshift(n, 56), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 48), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 40), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 32), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 24), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 16), 0xff)
    bytes[#bytes + 1] = band(rshift(n, 8), 0xff)
    bytes[#bytes + 1] = band(n, 0xff)
end

local function val_len(val)
    return val and strlen(val) or 0x00
end

local function extra_data(flags, expir)
    local bytes = {}
    set_byte4(bytes, flags)
    set_byte4(bytes, expir)
    return strchar(bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
end

local packet_meta = {}
local packet_mt = { __index = packet_meta }

function packet_meta:create_request(...)
    local req = {
        magic = 0x80,
        opcode = 0x00,
        key_len = 0x00,
        extra_len = 0x00,
        data_type = 0x00,
        vbucket_id = 0x00,
        total_len = 0x00,
        opaque = 0x00,
        cas = 0x00,
        extra = nil,
        key = nil,
        value = nil,
    }
    for k, v in pairs(...) do
        req[k] = v
    end
    setmetatable(req, packet_mt)
    return req
end

function packet_meta:create_response(...)
    local resp = {
        magic = 0x81,
        opcode = 0x00,
        key_len = 0x00,
        extra_len = 0x00,
        data_type = 0x00,
        status = 0x00,
        total_len = 0x00,
        opaque = 0x00,
        cas = 0x00,
        extra = nil,
        key = nil,
        value = nil,
    }
    for k, v in pairs(...) do
        resp[k] = v
    end
    setmetatable(resp, packet_mt)
    return resp
end

function packet_meta:send_packet(sock)
    local packet = self
    packet.key_len = val_len(packet.key)
    packet.extra_len = val_len(packet.extra)
    packet.total_len = packet.key_len + packet.extra_len + val_len(packet.value)

    local header = {}
    set_byte(header, packet.magic)
    set_byte(header, packet.opcode)
    set_byte2(header, packet.key_len)

    set_byte(header, packet.extra_len)
    set_byte(header, packet.data_type)
    set_byte2(header, packet.vbucket_id)

    set_byte4(header, packet.total_len)
    set_byte4(header, packet.opaque)
    set_byte8(header, packet.cas)

    local bytes = {}
    bytes[#bytes + 1] = byte2str(header)
    bytes[#bytes + 1] = packet.extra
    bytes[#bytes + 1] = packet.key
    bytes[#bytes + 1] = packet.value

    return sock:send(table_concat(bytes))
end

local values = { 'extra', 'key', 'value' }

function packet_meta:read_packet(sock)
    local data, err = sock:receive(24)
    if not data then
        return nil, "failed to receive packet header: " .. err
    end

    local packet = self
    packet.magic = strbyte(data, 1)
    packet.opcode = strbyte(data, 2)
    packet.key_len = get_byte2(data, 3)

    packet.extra_len = strbyte(data, 5)
    packet.data_type = strbyte(data, 6)
    packet.status = get_byte2(data, 7)

    packet.total_len = get_byte4(data, 9)
    packet.opaque = get_byte4(data, 13)
    packet.cas = get_byte8(data, 17)

    local value_len = packet.total_len - packet.extra_len - packet.key_len
    local val_config = { extra = packet.extra_len, key = packet.key_len, value = value_len }
    for _, name in ipairs(values) do
        local len = val_config[name]
        if len > 0 then
            local val_data, val_err = sock:receive(len)
            if not val_data then
                return nil, "failed to receive packet: " .. val_err
            end
            packet[name] = val_data
        end
    end

    if packet.extra then
        -- We just same to ngx_http_memcached_module.
        local flag = get_byte4(packet.extra, 1)
        if band(flag, 0x0002) ~= 0 then
            ngx.header['Content-Encoding'] = 'gzip'
            -- sub_request does not get the Content-Encoding value.
            if ngx.is_subrequest then
                ngx.header['Sub-Req-Content-Encoding'] = 'gzip'
            end
        end
        -- Only support bool int long specil_data byte
        if flag == 0x100 then
            packet.value = strbyte(packet.value) == 0x31
        elseif flag > 0x100 and flag < 0x600 then
            local raw_value, num = packet.value, 0
            if value_len > 3 then
                -- BitOp is Only support the 32 bit. we just workround it.
                -- http://bitop.luajit.org/semantics.html
                local hex_num = { '0x' }
                for i = 1, value_len, 1 do
                    hex_num[#hex_num + 1] = tohex(strbyte(raw_value, i), 2)
                end
                num = tonumber(table_concat(hex_num, ''), 16)
            else
                for i = 1, value_len, 1 do
                    num = bor(lshift(num, 8), strbyte(raw_value, i))
                end
            end
            packet.value = num
        end
    end

    return packet
end

local function prcess_sock_packet(sock, packet)
    local bytes, err = packet:send_packet(sock)
    if not bytes then
        return nil, "failed to send packet: " .. err
    end
    return packet:read_packet(sock)
end

local opcodes = {
    -- base opcode
    Get = 0x00,
    Set = 0x01,
    Add = 0x02,
    Replace = 0x03,
    Delete = 0x04,
    Increment = 0x05,
    Decrement = 0x06,
    Quit = 0x07,
    Flush = 0x08,
    -- adv opcode
    GetQ = 0x09,
    ['No-op'] = 0x0A,
    Version = 0x0B,
    GetK = 0x0C,
    GetKQ = 0x0D,
    Append = 0x0E,
    Prepend = 0x0F,
    Stat = 0x10,
    SetQ = 0x11,
    AddQ = 0x12,
    ReplaceQ = 0x13,
    DeleteQ = 0x14,
    IncrementQ = 0x15,
    DecrementQ = 0x16,
    QuitQ = 0x17,
    FlushQ = 0x18,
    AppendQ = 0x19,
    PrependQ = 0x1A,
    -- SASL opcode
    SASList = 0x20,
    SASLAuth = 0x21,
    SASLStep = 0x22,
    GetFromReplica = 0x83,
    -- cluster
    GetClusterConfig = 0xb5
}

local opcode_quiet = {
    [opcodes.Get] = opcodes.GetQ,
    [opcodes.Set] = opcodes.SetQ,
    [opcodes.Add] = opcodes.AddQ,
    [opcodes.Replace] = opcodes.ReplaceQ,
    [opcodes.Delete] = opcodes.DeleteQ,
    [opcodes.Increment] = opcodes.IncrementQ,
    [opcodes.Decrement] = opcodes.DecrementQ,
    [opcodes.Quit] = opcodes.QuitQ,
    [opcodes.Flush] = opcodes.FlushQ,
    [opcodes.GetK] = opcodes.GetKQ,
}

local status_code = {
    [0x0000] = 'No error',
    [0x0001] = 'Key not found',
    [0x0002] = 'Key exists',
    [0x0003] = 'Value too large',
    [0x0004] = 'Invalid arguments',
    [0x0005] = 'Item not stored',
    [0x0006] = 'Incr/Decr on non-numeric value',
    [0x0007] = 'Vbucket belongs to another server',
    [0x0081] = 'Unknown command',
    [0x0082] = 'Out of memory',
}

_M._unused_f2 = status_code

local function sasl_list(sock)
    local request_packet = packet_meta:create_request({
        opcode = opcodes.SASList
    })
    local packet, err = prcess_sock_packet(sock, request_packet)
    if not packet then
        return nil, "failed to test hmac: " .. err
    end

    if string.find(packet.value, 'CRAM%-MD5') then
        return true
    end
    return nil, 'not support sasl'
end

local function sasl_auth(sock)
    local packet = packet_meta:create_request({
        opcode = opcodes.SASLAuth,
        key = 'CRAM-MD5',
    })
    local sasl_packet, err = prcess_sock_packet(sock, packet)
    if not sasl_packet then
        return nil, "failed to get challenge: " .. err
    end
    return sasl_packet.value
end

local function sasl_step(sock, vbucket, challenge)
    local token = hmac(vbucket.password, challenge)

    local packet = packet_meta:create_request({
        opcode = opcodes.SASLStep,
        key = 'CRAM-MD5',
        value = vbucket.name .. ' ' .. token,
    })

    local step_packet, err = prcess_sock_packet(sock, packet)
    if not step_packet then
        return nil, "failed to do chanllenge: " .. err
    end
    return (step_packet.value == 'Authenticated' or step_packet.value ~= 'Auth failure') or nil, step_packet.value
end

local function get_pool_name(client, server)
    return server.host .. ':' .. server.port .. ':' .. client.vbucket.name
end

local function get_socks(client, pool_name)
    if not client.socks[pool_name] then
        local sock, err = tcp()
        if not sock then
            return nil, err
        end
        sock:settimeout(default_timeout)
        client.socks[pool_name] = sock
    end
    return client.socks[pool_name]
end

local function create_connect(client, server)
    local pool_name = get_pool_name(client, server)
    local sock, err = get_socks(client, pool_name)
    if not sock then
        return nil, 'failed to create tcp: ' .. err
    end

    local ok, connect_err = sock:connect(server.host, server.port, { pool = pool_name })
    if not ok then
        return nil, 'failed to connect: ' .. connect_err
    end

    local reused = sock:getreusedtimes()
    if not (reused and reused > 0) then
        log_info('try to auth : host=', server.host, ',port=', server.port, ',bucket=', client.vbucket.name)

        local list, sasl_err = sasl_list(sock)
        if not list then
            return nil, sasl_err
        end

        local challenge, auth_err = sasl_auth(sock)
        if not challenge then
            return nil, 'failed to sasl auth: ' .. auth_err
        end

        local has_auth, step_err = sasl_step(sock, client.vbucket, challenge)
        if not has_auth then
            return nil, 'failed to sasl step: ' .. step_err
        end
    end
    return sock
end

local function group_packet_by_sock(client, packets)
    local vbucket = client.vbucket
    local socks, servers, errors = {}, {}, {}
    for _, packet in ipairs(packets) do
        local server = location_server(vbucket, packet)
        local sock = servers[server]
        if not sock and not errors[server] then
            local connect, err = create_connect(client, server)
            if not connect then
                if string.find(err, 'connection refused') then
                    reload_vbucket(client.vbucket)
                end
                if string.find(err, 'no resolver defined to resolve') then
                    log_error(
                        'You need config nginx resolver. '
                        .. 'http://nginx.org/en/docs/http/ngx_http_core_module.html#resolver')
                end
                errors[#errors + 1] = { server = server, err = err }
            else
                sock = connect
                servers[server] = sock
                socks[sock] = {}
            end
        end
        if socks[sock] then
            local pks = socks[sock]
            pks[#pks + 1] = packet
        end
    end
    if #errors > 0 then
        log_info('group_packet_by_sock has some errors. errors=', cjson.encode(errors))
        return nil, cjson.encode(errors)
    end
    return socks
end

local function rewrite_packet(socks)
    for _, packets in pairs(socks) do
        if #packets > 1 then
            local last = #packets - 1
            for _ = 1, last, 1 do
                packet_meta.opcode = opcode_quiet[packet_meta.opcode]
            end
        end
    end
end

local function process_multi_packets(client, packets)
    local resps, errors = {}, {}

    local socks, err = group_packet_by_sock(client, packets)
    if not socks then
        return nil, err
    end
    rewrite_packet(socks)

    for sock, sock_packets in pairs(socks) do
        for _, packet in ipairs(sock_packets) do
            local bytes, send_err = packet:send_packet(sock)
            if not bytes then
                errors[packet] = send_err
            end
        end
    end

    for sock, sock_packets in pairs(socks) do
        for _, packet in ipairs(sock_packets) do
            if errors[packet] == nil then
                local resp, read_err = packet:read_packet(sock)
                if not resp then
                    errors[packet] = read_err
                else
                    -- This is a common during rebalancing after adding or removing a node or during a failover.
                    if resp.status == 0x0007 then
                        reload_vbucket(client.vbucket)
                    end
                    resps[#resps + 1] = resp
                end
            end
        end
        sock:setkeepalive(pool_max_idle_timeout, pool_size)
    end

    if #errors > 0 then
        log_info('process_multi_packets has some errors. errors=', cjson.encode(errors))
    end

    return resps
end

local function process_packet(client, packet)
    local packets, err = process_multi_packets(client, { packet })
    if not (packets and packets[1]) then
        return nil, err
    end

    local resp = packets[1]
    if resp.status ~= 0x0 then
        return nil, resp.value
    end
    return resp.value or resp.status
end

local function n1ql_config(client)
    local n1ql_nodes = client.n1ql_nodes
    if #n1ql_nodes > 0 then
        return
    end

    local req_packet = packet_meta:create_request({
        opcode = opcodes.GetClusterConfig,
        key = '',
    })

    local value, err = process_packet(client, req_packet)
    if not value then
        return nil, "failed to get cluster config.: " .. err
    end

    local config = cjson.decode(value)
    local nodes = config['nodesExt']
    for _, node in ipairs(nodes) do
        local services = node['services']
        if services.n1ql then
            n1ql_nodes[#n1ql_nodes + 1] = { node.hostname, services.n1ql }
        end
    end
end

local query_service = '/query/service?'

local function query_n1ql(n1ql_nodes, n1ql)
    local n1ql_node = n1ql_nodes[random(1, #n1ql_nodes)]
    local resp = http_request(n1ql_node[1], n1ql_node[2], query_service .. ngx_encode_args({ statement = n1ql }))
    return cjson.decode(resp)
end

function vbuckets:bucket(host_ports, bucket_name, password, cluster)
    local clustername = cluster or "default"
    local clu = vbuckets[clustername]
    if not clu then
        vbuckets[clustername] = {}
    end
    local vbucket = vbuckets[clustername][bucket_name]
    if not vbucket then
        local fetch_able = ldict:safe_add(
            'couchbae_fetch_config' .. (ngx_crc32(tostring(ngx.ctx)) % 20
            + ngx_crc32(tostring(clustername)) % 20), 0, 1)
        if fetch_able then
            vbucket = create_vbucket(host_ports, bucket_name, password)
            if not vbucket then
                return nil, 'fail to build bucket'
            end
            vbuckets[clustername][bucket_name] = vbucket
        else
            ngx.sleep(0.5)
        end
        vbucket = vbuckets[clustername][bucket_name]
        if vbucket then
            return vbucket
        end
    end
    return vbucket
end

function _M:create_client(host_ports, bucket_name, password, cluster)
    local client = {
        vbucket = vbuckets:bucket(host_ports, bucket_name, password, cluster),
        socks = {},
        n1ql_nodes = {},
    }
    if not client.vbucket then
        return nil, 'fail to create_client'
    end
    setmetatable(client, mt)
    return client
end

function _M:get(key)

    local req_packet = packet_meta:create_request({
        opcode = opcodes.Get,
        key = key,
    })

    local value, err = process_packet(self, req_packet)
    if not value then
        return nil, "failed to get key: " .. tostring(err)
    end

    return value
end

function _M:get_from_replica(key)

    local req_packet = packet_meta:create_request({
        opcode = opcodes.GetFromReplica,
        key = key,
        is_replica = true,
    })

    local value, err = process_packet(self, req_packet)
    if not value then
        return nil, "failed to get key from replica: " .. tostring(err)
    end

    return value
end

function _M:set(key, value, expir)

    local req_packet = packet_meta:create_request({
        opcode = opcodes.Set,
        key = key,
        value = value,
        -- TODO suppot gzip.
        extra = extra_data(0x0, expir or 0x0)
    })

    local ori_value, err = process_packet(self, req_packet)
    if not ori_value then
        return nil, "failed to set key: " .. tostring(err)
    end
    return ori_value
end

function _M:delete(key)

    local req_packet = packet_meta:create_request({
        opcode = opcodes.Delete,
        key = key,
    })

    local value, err = process_packet(self, req_packet)
    if not value then
        return nil, "failed to delete key: " .. tostring(err)
    end
    return value
end

function _M:get_bluk(...)
    local resp_values = {}

    local req_packets = {}
    for _, key in ipairs({ ... }) do
        req_packets[#req_packets + 1] = packet_meta:create_request({
            opcode = opcodes.Get,
            key = key,
        })
    end

    local resp_packets, err = process_multi_packets(self, req_packets)
    if not resp_packets then
        return nil, "failed to get_bluk: " .. tostring(err)
    end

    for _, packet in ipairs(resp_packets) do
        if packet.status == 0x0 then
            resp_values[packet.key] = packet.value
        end
    end

    return resp_values
end

function _M:query(n1ql)
    n1ql_config(self)
    local n1ql_nodes = self.n1ql_nodes
    if #n1ql_nodes == 0 then
        return nil, 'server is not support the N1QL.'
    end

    local value = query_n1ql(n1ql_nodes, n1ql)
    if value.status == 'success' then
        return value.results
    end

    return nil, value.errors[1]
end

function _M:set_timeout(timeout)
    local socks = self.socks
    for _, sock in pairs(socks) do
        sock:settimeout(timeout)
    end
end

function _M:close()
    local socks = self.socks
    for _, sock in pairs(socks) do
        sock:close()
    end
end

return _M