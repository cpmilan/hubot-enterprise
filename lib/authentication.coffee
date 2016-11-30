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
auth = require('he-auth-service')
Promise = require('bluebird')
auth_service = require('he-auth-service')
auth_client = auth_service.client
auth_lib = auth_service.lib
promisified_client = Promise.promisifyAll(auth_client)
TYPES =
  BASIC_AUTH: auth_lib.authMethods.BASIC_AUTH

env =
  ENDPOINT: 'HE_AUTH_SERVICE_ENDPOINT'
  ENABLE: 'HE_ENABLE_AUTH'

errors =
  no_type: new Error('Must provide authentication type!')
  unsupported_type: new Error('Specified type is not supported')
  not_enabled: new Error('Please set the ' + env.ENABLE + ' and ' +
      env.ENDPOINT + ' env vars')

values =
  # Default to 30 minute token expiration
  DEFAULT_TOKEN_TTL: 1800

generate_basic_auth = (params) ->
  return {
    type: TYPES.BASIC_AUTH,
    params: params
  }

setup_auth_client = (robot) ->
  auth_enabled = process.env.HE_ENABLE_AUTH || false
  he_auth_service_endpoint = process.env.HE_AUTH_SERVICE_ENDPOINT || false

  if !auth_enabled || !he_auth_service_endpoint
    robot.logger.debug('Authentication is not enabled')
    return null

  config =
    endpoint: he_auth_service_endpoint

  client = new promisified_client.AuthServiceClient(config)
  return client


module.exports =
  TYPES: TYPES
  errors: errors
  generate_basic_auth: generate_basic_auth
  setup_auth_client: setup_auth_client
  env: env
  client: auth_client
  values: values
