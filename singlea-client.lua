--
-- SPDX-License-Identifier: BSD-3-Clause
--
-- Usage:
--
-- (1) Login if necessary, request user token and add it into an original request
--     with custom client parameters:
--
-- server {
--   location ~ ^/any$ {
--     rewrite_by_lua_block {
--        require("singlea-client").new {
--           client_id = "hard_coded_client_id",
--           request_timeout = 10,
--           token_header = "Custom-Authorization",
--        }
--           :login()
--           :token()
--     }
--     # ...
--   }
-- }
--
--
-- (2) Request user token if authenticated only and flush the token if required:
--
-- server {
--   location ~ ^/any$ {
--     rewrite_by_lua_block {
--        require("singlea-client").new()
--           :token(false)
--     }
--
--     # Some request processing, e.g. with FastCGI
--     # ...
--
--     header_filter_by_lua_block {
--        require("singlea-client").new()
--           :flush_token()
--     }
--   }
-- }
--
--
-- (3) Validate user session only:
--
-- server {
--   location ~ ^/any$ {
--     rewrite_by_lua_block {
--        require("singlea-client").new()
--           :validate()
--     }
--     # ...
--   }
-- }
--


local base64 = require "base64"
local http_util = require "http.util"
local resty_http = require "resty.http"
local pkey = require "openssl.pkey"
local digest = require "openssl.digest"

local DEFAULT_LOGIN_PATH = "/login"
local DEFAULT_LOGOUT_PATH = "/logout"
local DEFAULT_VALIDATE_PATH = "/validate"
local DEFAULT_TOKEN_PATH = "/token"

local DEFAULT_ENV_PREFIX = "SINGLEA_"
local DEFAULT_REALM_QUERY_PARAM = "realm"
local DEFAULT_CLIENT_ID_QUERY_PARAM = "client_id"
local DEFAULT_SECRET_QUERY_PARAM = "secret"
local DEFAULT_REDIRECT_URI_QUERY_PARAM = "redirect_uri"
local DEFAULT_SIGNATURE_QUERY_PARAM = "sg"
local DEFAULT_TIMESTAMP_QUERY_PARAM = "ts"
local DEFAULT_SIGNATURE_MD_ALGORITHM = "SHA256"
local DEFAULT_TICKET_COOKIE_NAME = "tkt"
local DEFAULT_TICKET_HEADER = "X-Ticket"
local DEFAULT_TOKEN_DICT = "tokens"
local DEFAULT_TOKEN_HEADER = "Authorization"
local DEFAULT_TOKEN_PREFIX = "Bearer "
local DEFAULT_TOKEN_FLUSH_HEADER = "X-Flush-Token"
local DEFAULT_REQUEST_TIMEOUT = 30

local base64_url_encoder = base64.makeencoder("-", "_")


local function add_signature(query_params, config)
   query_params[config.timestamp_query_param] = tostring(os.time())

   local param_names = {}
   for param in pairs(query_params) do
      table.insert(param_names, param)
   end
   table.sort(param_names)

   local param_values = {}
   for index, param in ipairs(param_names) do
      table.insert(param_values, index, query_params[param])
   end

   local successful, error, data, signature

   successful, error = pcall(function()
      data = digest.new(config.signature_md_algorithm)
      data:update(table.concat(param_values, "."))
   end)

   if not successful then
      ngx.log(ngx.CRIT, "Cannot create message digest instance: " .. error)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end

   successful, error = pcall(function()
      signature = config.signature_key:sign(data)
   end)

   if not successful then
      ngx.log(ngx.CRIT, "Signature failed: " .. error)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end

   query_params[config.signature_query_param] = base64.encode(signature, base64_url_encoder)
end

local function do_request(config, uri)
   local ticket = assert(ngx.var["cookie_" .. config.ticket_cookie_name], "Ticket cookie should be defined")

   local query_params = {
      [config.client_id_query_param] = config.client_id,
      [config.secret_query_param] = config.secret,
      [config.realm_query_param] = config.realm,
   }
   if config.signature_key then
      add_signature(query_params, config)
   end

   local url = config.base_url .. uri .. "?" .. http_util.dict_to_query(query_params)

   local httpc = resty_http.new()
   local response, error = httpc:request_uri(url, {
      method = "GET",
      headers = {
         [config.ticket_header] = ticket,
      },
      keepalive_timeout = config.request_timeout,
      ssl_verify = config.ssl_verify,
   })

   if not response then
      ngx.log(ngx.CRIT, "Failed to request (" .. url .. "): " .. error)
      ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
   end

   return response
end

local function make_redirect(config, path, redirect_uri)
   local query_params = {
      [config.client_id_query_param] = config.client_id,
      [config.secret_query_param] = config.secret,
      [config.redirect_uri_query_param] = redirect_uri,
      [config.realm_query_param] = config.realm,
   }
   if config.signature_key then
      add_signature(query_params, config)
   end

   return ngx.redirect(config.base_url .. path .. "?" .. http_util.dict_to_query(query_params))
end


return {
   new = function (params)
      params = params or {}
      local env_prefix = params.env_prefix or DEFAULT_ENV_PREFIX

      local signature_key = params.signature_key or os.getenv(env_prefix .. "SIGNATURE_KEY")
      if signature_key ~= nil then
         local successful, error

         successful, error = pcall(function ()
            signature_key = pkey.new(signature_key)
         end)

         if not successful then
            ngx.log(ngx.CRIT, "Cannot read signature private key: " .. error)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
         end
      end

      local config = {
         base_url                   = assert(params.base_url              or os.getenv(env_prefix .. "BASE_URL"),                  "SingleA base url should be specified"),
         client_id                  = assert(params.client_id             or os.getenv(env_prefix .. "CLIENT_ID"),                 "Client ID should be specified"),
         secret                     = assert(params.secret                or os.getenv(env_prefix .. "SECRET"),                    "Client secret should be specified"),

         client_id_query_param      = params.client_id_query_param        or os.getenv(env_prefix .. "CLIENT_ID_QUERY_PARAM")      or DEFAULT_CLIENT_ID_QUERY_PARAM,
         secret_query_param         = params.secret_query_param           or os.getenv(env_prefix .. "SECRET_QUERY_PARAM")         or DEFAULT_SECRET_QUERY_PARAM,
         redirect_uri_query_param   = params.redirect_uri_query_param     or os.getenv(env_prefix .. "REDIRECT_URI_QUERY_PARAM")   or DEFAULT_REDIRECT_URI_QUERY_PARAM,
         realm_query_param          = params.realm_query_param            or os.getenv(env_prefix .. "REALM_QUERY_PARAM")          or DEFAULT_REALM_QUERY_PARAM,
         timestamp_query_param      = params.timestamp_query_param        or os.getenv(env_prefix .. "TIMESTAMP_QUERY_PARAM")      or DEFAULT_TIMESTAMP_QUERY_PARAM,
         signature_query_param      = params.signature_query_param        or os.getenv(env_prefix .. "SIGNATURE_QUERY_PARAM")      or DEFAULT_SIGNATURE_QUERY_PARAM,
         ticket_cookie_name         = params.ticket_cookie_name           or os.getenv(env_prefix .. "TICKET_COOKIE_NAME")         or DEFAULT_TICKET_COOKIE_NAME,
         ticket_header              = params.ticket_header                or os.getenv(env_prefix .. "TICKET_HEADER")              or DEFAULT_TICKET_HEADER,
         signature_md_algorithm     = params.signature_md_algorithm       or os.getenv(env_prefix .. "SIGNATURE_MD_ALGORITHM")     or DEFAULT_SIGNATURE_MD_ALGORITHM,
         token_dict                 = params.token_dict                   or os.getenv(env_prefix .. "TOKEN_DICT")                 or DEFAULT_TOKEN_DICT,
         token_header               = params.token_header                 or os.getenv(env_prefix .. "TOKEN_HEADER")               or DEFAULT_TOKEN_HEADER,
         token_prefix               = params.token_prefix                 or os.getenv(env_prefix .. "TOKEN_PREFIX")               or DEFAULT_TOKEN_PREFIX,
         token_flush_header         = params.token_flush_header           or os.getenv(env_prefix .. "TOKEN_FLUSH_HEADER")         or DEFAULT_TOKEN_FLUSH_HEADER,
         request_timeout            = tonumber(params.request_timeout     or os.getenv(env_prefix .. "REQUEST_TIMEOUT")            or DEFAULT_REQUEST_TIMEOUT),
         ssl_verify                 = (params.ssl_not_verify              or os.getenv(env_prefix .. "SSL_NOT_VERIFY")             or '') == '',
         client_base_url            = params.client_base_url              or os.getenv(env_prefix .. "CLIENT_BASE_URL")            or ngx.var.scheme .. "://" .. ngx.var.http_host,
         realm                      = params.realm                        or os.getenv(env_prefix .. "REALM"),
         signature_key              = signature_key
      }

      local login_path    = params.login_path    or os.getenv(env_prefix .. "LOGIN_PATH")    or DEFAULT_LOGIN_PATH
      local logout_path   = params.logout_path   or os.getenv(env_prefix .. "LOGOUT_PATH")   or DEFAULT_LOGOUT_PATH
      local validate_path = params.validate_path or os.getenv(env_prefix .. "VALIDATE_PATH") or DEFAULT_VALIDATE_PATH
      local token_path    = params.token_path    or os.getenv(env_prefix .. "TOKEN_PATH")    or DEFAULT_TOKEN_PATH

      return {
         login = function (self)
            if ngx.var["cookie_" .. config.ticket_cookie_name] ~= nil then
               local response = do_request(config, validate_path)
               if response.status == ngx.HTTP_OK then
                  return self
               end
            end

            if ngx.var.http_x_requested_with == "XMLHttpRequest" then
               ngx.exit(ngx.HTTP_UNAUTHORIZED)
            end

            local redirect_uri = config.client_base_url .. ngx.var.request_uri
            if (ngx.var.args or '') ~= '' then
               redirect_uri = redirect_uri .. "?" .. ngx.var.args
            end

            return make_redirect(config, login_path, redirect_uri)
         end,

         logout = function ()
            if ngx.var["cookie_" .. config.ticket_cookie_name] == nil then
               return
            end

            local redirect_uri = config.client_base_url .. ngx.var.request_uri
            if (ngx.var.args or '') ~= '' then
               redirect_uri = redirect_uri .. "?" .. ngx.var.args
            end

            return make_redirect(config, logout_path, redirect_uri)
         end,

         validate = function (self)
            if ngx.var["cookie_" .. config.ticket_cookie_name] ~= nil then
               local response = do_request(config, validate_path)
               if response.status == ngx.HTTP_OK then
                  return self
               end
            end

            ngx.exit(ngx.HTTP_UNAUTHORIZED)
         end,

         token = function (self, auth_required)
            if (ngx.var["cookie_" .. config.ticket_cookie_name] == nil) then
               if auth_required == false then
                  return
               end

               ngx.exit(ngx.HTTP_UNAUTHORIZED)
            end

            local dict, key = ngx.shared[config.token_dict], config.client_id .. ngx.var["cookie_" .. config.ticket_cookie_name]

            if ngx.req.get_headers()[config.token_flush_header] ~= nil then
               local _, delete_error = dict:delete(key)
               if delete_error then
                  ngx.log(ngx.ERR, "Delete token from shared dictionary error: " .. delete_error)
               end
            end

            local token, get_error = dict:get(key)
            if token == nil and get_error then
               ngx.log(ngx.ERR, "Get token from shared dictionary error: " .. get_error)
            end

            if token == nil then
               local response = do_request(config, token_path)
               if response.status ~= ngx.HTTP_OK then
                  if auth_required == false then
                     return
                  end

                  ngx.exit(ngx.HTTP_UNAUTHORIZED)
               end

               token = response.body
               if token == nil then
                  ngx.log(ngx.ERR, "Response does not contain token (header is empty or does not exist)")
                  ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
               end

               local exptime = 0
               local cache_control = response.headers["cache-control"]

               if cache_control ~= nil then
                  local max_age, ok = cache_control:gsub("max%-age=(%d+).*", "%1")
                  if ok then
                     exptime = tonumber(max_age)
                  end
               end

               local success, set_error, forcible = dict:set(key, token, exptime)
               if not success and set_error then
                  ngx.log(ngx.ERR, "Set token into shared dictionary error: " .. set_error)
               end

               if forcible then
                  ngx.log(ngx.WARN, "Token was forced into shared memory")
               end
            end

            ngx.req.set_header(config.token_header, config.token_prefix .. token)

            return self
         end,

         flush_token = function (force)
            if force ~= true and ngx.header[config.token_flush_header] == nil then
               return
            end

            if (ngx.var["cookie_" .. config.ticket_cookie_name] == nil) then
               ngx.log(ngx.WARN, "No ticket cookie, cannot drop token")
               return
            end

            local dict, key = ngx.shared[config.token_dict], config.client_id .. ngx.var["cookie_" .. config.ticket_cookie_name]
            local _, delete_error = dict:delete(key)
            if delete_error then
               ngx.log(ngx.ERR, "Delete token from shared dictionary error: " .. delete_error)
            end
         end,
      }
   end
}
