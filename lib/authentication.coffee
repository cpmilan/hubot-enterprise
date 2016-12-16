# Notes:
#  Copyright 2016 Hewlett-Packard Development Company, L.P.
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  and/or sell copie of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
auth = require 'he-auth-service'
Promise = require 'bluebird'
auth_service = require 'he-auth-service'
logger = require 'winston'
_ = require 'lodash'
auth_client = auth_service.client
auth_lib = auth_service.lib
promisified_client = Promise.promisifyAll(auth_client)


TYPES =
  BASIC_AUTH: auth_lib.AUTH_METHODS.BASIC_AUTH
  IDM_AUTH: auth_lib.AUTH_METHODS.IDM_AUTH

VERBS = auth_lib.SUPPORTED_VERBS

env =
  ENDPOINT: 'HE_AUTH_SERVICE_ENDPOINT'
  ENABLE: 'HE_ENABLE_AUTH'

errors =
  no_type: new Error('Must provide authentication type!')
  unsupported_type: new Error('Specified type is not supported')
  not_enabled: new Error('Please set the ' + env.ENABLE + ' and ' +
      env.ENDPOINT + ' env vars')
  failed_validation: new Error('Integration authentication configuration failed validation.')

values =
  # Default to 30 minute token expiration
  DEFAULT_TOKEN_TTL: 1800

BASIC_AUTH_DOCS = "https://github.com/eedevops/hubot-enterprise/wiki/api#supported-authentication-types"

# Validates the authentication object passed.
# Returns a validated auth object or null if validation failed.
validate_authentication = (authentication) ->
  if !authentication
    authString = JSON.stringify(authentication, ' ', 2)
    msg = "Empty authentication configuration passed #{authString}"
    logger.error(msg)
    return null

  if !_.includes(TYPES, authentication.type)
    msg = "Invalid authentication type selected #{authentication.type}"
    logger.error(msg)
    return null

  # Generate the appropriate auth object based on its type.
  switch authentication.type
    when TYPES.BASIC_AUTH
      try
        auth = generate_basic_auth(authentication.params)
        return auth
      catch e
        logger.error(e)
        return null
    when TYPES.IDM_AUTH
      try
        auth = generate_idm_auth(authentication.params)
        return auth
      catch e
        logger.error(e)
        return null
    else
      msg = "Invalid authentication type selected #{authentication.type}"
      logger.error(msg)
      return null

format_auth_object = (auth_type, params) ->
  return {
    type: auth_type,
    params: params
  }

# Throws an error if any constraint fails
validate_tenant_params = (tenant_params) ->
  logger.debug("Validating tenant params #{JSON.stringify(tenant_params)}")
  # Should cover undef case
  if not _.isObject(tenant_params)
    msg = "Tenant params is not of valid type = #{JSON.stringify(tenant_params)}"
    logger.error(msg)
    throw new Error(msg)

  username = tenant_params.username
  password = tenant_params.password
  name = tenant_params.name

  if not _.isString(name) or _.isEmpty(name)
    msg = "Tenant name is not valid = #{JSON.stringify(name)}"
    logger.error(msg)
    throw new Error(msg)

  if not _.isString(username) or _.isEmpty(username)
    msg = "Tenant username is not valid = #{JSON.stringify(username)}"
    logger.error(msg)
    throw new Error(msg)

  if not _.isString(password) or _.isEmpty(password)
    msg = "Tenant password is not valid = #{JSON.stringify(password)}"
    logger.error(msg)
    throw new Error(msg)


# TODO: needs refactoring :)
# Throws an error if any constraint fails
validate_endpoint_params = (endpoint, type) ->
  if not endpoint
    msg = "You have an empty endpoint in your params: #{endpoint}"
    throw new Error(msg)

  if typeof endpoint != "object"
    msg = "Please refer to the authentication docs: #{BASIC_AUTH_DOCS}"
    msg = "Using params.endpoint must be an object. #{msg}"
    msg = "#{msg}. endpoint = #{JSON.stringify(endpoint, ' ', 2)}"
    logger.error(msg);
    throw new Error(msg)

  if not endpoint.url
    msg = "Auth endpoint configuration is missing url: #{JSON.stringify(endpoint, ' ', 2)}"
    logger.error(msg)
    throw new Error(msg)

  if _.isEmpty(endpoint.url)
    msg = "Auth endpoint url is empty: #{JSON.stringify(endpoint, ' ', 2)}"
    logger.error(msg)
    throw new Error(msg)

  if not _.isString(endpoint.url)
    msg = "Auth endpoint url should be a string: #{JSON.stringify(endpoint, ' ', 2)}"
    logger.error(msg)
    throw new Error(msg)

  if not endpoint.verb
    msg = "Auth endpoint configuration is missing verb: #{JSON.stringify(endpoint, ' ', 2)}"
    logger.error(msg)
    throw new Error(msg)

  # Should cover strange value cases (e.g. Numeric, Object)
  if not _.includes(VERBS, endpoint.verb)
    msg = "Auth endpoint verb is not supported: #{endpoint.verb}"
    logger.error(msg)
    throw new Error(msg)

  if type == TYPES.IDM_AUTH
    if typeof endpoint.verb != "string" or endpoint.verb != "POST"
      msg = "Only POST verb supported for idm_auth endpoint"
      logger.error(msg)
      throw new Error(msg)


create_basic_auth_config = (endpoint_url, endpoint_verb) ->
  params =
    endpoint:
      url: endpoint_url
      verb: endpoint_verb
  return generate_basic_auth(params)

create_idm_auth_config = (endpoint_url, tenant_username, tenant_password, tenant_name) ->
  params =
    endpoint:
        url: endpoint_url
        # Hardcode to POST since this is the current standard.
        verb: "POST"

  if tenant_password or tenant_username or tenant_name
    params.tenant = {}
    params.tenant.username = tenant_username
    params.tenant.password = tenant_password
    params.tenant.name = tenant_name

  return generate_idm_auth(params)

# Convenience method to generate BasicAuth object for registration.
# Throws exception when validation fails.
generate_basic_auth = (params) ->
  auth = null
  # Validate structure of endpoint
  if params?
    msg = JSON.stringify(params, ' ', 2)
    msg = "Parameters passed for BasicAuth configuration #{msg}"
    logger.info(msg)

    # Throws exception
    try
      # Endpoint is optional for BasicAuth
      if _.has(params, 'endpoint')
        validate_endpoint_params(params.endpoint, params.type)
    catch e
      msg = JSON.stringify(params.endpoint, ' ', 2)
      msg = "Params failed validation #{msg}"
      msg = "#{msg}. Error = #{e.toString()}"
      logger.error msg
      # Bubble up
      throw e
  else
    msg = "basic_auth params are empty. Did you forget to specify endpoint?"
    logger.warning(msg)

  auth = format_auth_object(TYPES.BASIC_AUTH, params)

  logger.debug("Successfully generated BasicAuth: #{JSON.stringify(auth, ' ', 2)}")

  return auth

# Convenience method to generate IdMAuth object for registration.
# Throws exception when validation fails.
generate_idm_auth = (params) ->
  if not params or typeof params != "object"
    msg = JSON.stringify(params, ' ', 2)
    msg = "Missing required params object or invalid type: #{params}"
    logger.error(msg)
    throw new Error(msg)

  if not params.endpoint? or typeof params.endpoint != "object"
    msg = "Missing required endpoint or invalid type: #{params.endpoint}"
    logger.error(msg)
    throw new Error(msg)

  try
    # Endpoint is required for IdM
    validate_endpoint_params(params.endpoint, params.type)
  catch e
    msg = JSON.stringify(params.endpoint, ' ', 2)
    msg = "Params failed validation #{msg}"
    msg = "#{msg}. Error = #{e.toString()}"
    logger.error msg
    # Bubble up
    throw e

  # Tenant is optional, if present, needs to be validated.
  if params.tenant
    validate_tenant_params(params.tenant)

  auth = format_auth_object(TYPES.IDM_AUTH, params)

  logger.debug("Successfully generated IdMAuth: #{auth}")

  return auth

setup_auth_client = () ->
  logger.debug("HE_ENABLE_AUTH = #{process.env.HE_ENABLE_AUTH}")
  logger.debug("HE_AUTH_SERVICE_ENDPOINT = #{process.env.HE_AUTH_SERVICE_ENDPOINT}")

  auth_enabled = process.env.HE_ENABLE_AUTH || false
  he_auth_service_endpoint = process.env.HE_AUTH_SERVICE_ENDPOINT || false

  if !auth_enabled || !he_auth_service_endpoint
    logger.info('HE Authentication was NOT enabled.')
    return null

  config =
    endpoint: he_auth_service_endpoint

  logger.info("HE Authentication enabled with the following config: #{JSON.stringify(config, ' ', 2)}")

  client = new promisified_client.AuthServiceClient(config)
  return client


module.exports =
  TYPES: TYPES
  errors: errors
  generate_basic_auth: generate_basic_auth
  generate_idm_auth: generate_idm_auth
  setup_auth_client: setup_auth_client
  validate_authentication: validate_authentication
  create_basic_auth_config: create_basic_auth_config
  create_idm_auth_config: create_idm_auth_config
  env: env
  client: auth_client
  values: values
