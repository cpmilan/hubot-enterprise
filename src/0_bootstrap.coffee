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

# Bootstraping hubot-enterprise
# adding enterprise functions to robot object
Path = require('path')
Insight = require('insight')
_ = require 'lodash'
pkg = require('../package.json')
auth = require('../lib/authentication.coffee')
Adapter =
  insight = new Insight(
    trackingCode: process.env.HUBOT_HE_GA_CODE || 'UA-80724671-1'
    pkg: pkg)

insight.optOut = process.env.HUBOT_HE_OPT_OUT || false
insight.track 'HE', 'start'
help_words = ['info', 'menu', 'home', '\\?', 'support', 'help']
# contatination of help
reserverd_apps = help_words.concat([])
# HACK: adding 'enterprise' keyword after taking reserved apps, to avoid errors
# on this (enterprise) integration
help_words.push('enterprise')
inc_path = __dirname + '/../lib/'
module.exports = (robot) ->
  # Authentication is disabled by default
  # If a client is returned, then authentication was enabled and it is ready
  # to be used.
  auth_client = auth.setup_auth_client(robot)
  # Registrar object- store all integrations meta and info
  # Design specs:
  # https://github.com/eedevops/he-design/blob/master/hubot_enterprise.md#design
  # Automatically create with admin, admin will NEVER have auth
  # because it's not a real module
  registrar = {apps: {}, mapping: {}}

  # create e (enterprise object on robot)
  robot.e = {}

  # Inject authentication helpers
  robot.e.auth = auth

  # `mount` adapter object
  robot.e.adapter = new (require inc_path + 'adapter_core')(robot)

  commons = new (require inc_path + 'commons')()
  help = new (require inc_path + 'help')(robot, help_words)

  # set logging options
  winstonLogger = require ('winston')
  consoleOpts = {
    colorize: true,
    timestamp: true,
    level: process.env.LOG_LEVEL || 'debug'
  }

  transports = [new(winstonLogger.transports.Console)(consoleOpts)]
  if process.env.FLUENTD_HOST && process.env.FLUENTD_PORT
    FLUENTD_RECONNECT_DEFAULT = 600000
    FLUENTD_DEFAULT_TIMEOUT = 10
    logConfig = {
      host: process.env.FLUENTD_HOST,
      port: process.env.FLUENTD_PORT,
      timeout: process.env.FLUENTD_TIMEOUT || FLUENTD_DEFAULT_TIMEOUT,
      reconnectInterval: process.env.FLUENTD_RECONNECT || FLUENTD_RECONNECT_DEFAULT
    }
    FluentTransport = require('fluent-logger').support.winstonTransport()
    messagePrefix = process.env.FLUENTD_MSG_PREFIX || 'he'
    transports.push(new FluentTransport(messagePrefix,logConfig))

  winstonLogger.configure({
    transports: transports,
    exitOnError: false
  })
  winstonLogger.setLevels(winstonLogger.config.syslog.levels)

  robot.logger = winstonLogger
  # load scripts to robot
  load_he_scripts = (path) ->
    scriptsPath = Path.resolve ".", path
    robot.load scriptsPath

  # find integrations names: find by extracting integration name from
  # integration folder.
  # hubot-integration will become: `integration`
  find_integration_name = ->
    myError = new Error
    trace = myError.stack.split('\n')
    trace.shift()
    filename = __filename.replace(/[A-Za-z]:\\/, '').replace(/\\/ig, '/')
    fname = ''
    loop
      shift = trace.shift().replace(/[A-Za-z]:\\/, '').replace(/\\/ig, '/')
      fname = /\((.*):/i.exec(shift)[1].split(':')[0]
      unless fname == filename
        break
    integration_index = fname.lastIndexOf("hubot-")
    if integration_index > -1
      fname = '/' + fname.substring(integration_index)
      fmatch = fname.match(/\/hubot-(.*?)\//ig)
      return fmatch.pop().replace(/hubot-|\//g, '')
    # if not matched- return default 'script'
    else
      robot.logger.error("Integration name could not be extracted from path: " +
          "#{fname}")
      return 'script'

  # build extra part of the regex
  #
  # info: info object from build_enterprise_regex
  #  regex_suffix: extra element
  #    optional: true/false- should it be optional
  #    re: string that representing the regex (optional)
  build_extra_re = (info) ->
    # default values set for backward compatibility
    if (typeof info.extra == "string" && !info.regex_suffix)
      info.regex_suffix = {re: info.extra, optional: false}
    # init extra if its not there
    info.regex_suffix = info.regex_suffix || {optional: true, re: undefined}
    extra = info.regex_suffix
    if (typeof extra != "object")
      throw new Error("info.regex_suffix MUST be an object")
    # check that re is string or undefined
    if !_.includes(["undefined", "string"], (typeof extra.re))
      throw new Error("Cannot register a listener, info.regex_suffix.re must " +
          "be a string or undefined")
    # check that optional is boolean or undefined
    if !_.includes(["undefined", "boolean"], (typeof extra.optional))
      throw new Error("Cannot register a listener, " +
          "info.regex_suffix.optional " +
          "must be a boolean or undefined")
    # TODO: prevent calls similarity as much as possible
    # TODO: only one verb+entity may have optional: true
    # TODO: forbid {optional: true} with {re: null, optional: false}
    # TODO: try to check that 2 regexps are not equal (at least no the same)
    if extra.re
      # if extra.re passed and its optional
      if extra.optional
        return "(?: #{extra.re})?"
      #if it's not optional
      else
        return " #{extra.re}"
    #if no extra.re and optional
    else if extra.optional
      return '[ ]?(.*)?'
    #if no extra.re and not optional
    else
      return ''

  find_alias_by_name = (integration_name) ->
    return _.findKey(registrar.mapping, (o) ->
      return o == integration_name)

  registrar_add_call = (info, integration_name) ->
    mapping_name = find_alias_by_name(integration_name)
    verbs = registrar.apps[integration_name].verbs
    # init verb if not exists
    verbs[info.verb] = verbs[info.verb] || {flat: {}, entities: {}}
    verb = registrar.apps[integration_name].verbs[info.verb]
    # for calls with entity
    if info.entity
      # init entity if not exists
      verb.entities[info.entity] = verb.entities[info.entity] || {}
      # basic check for duplicates
      if verb.entities[info.entity][info.regex]
        throw new Error("Cannot register listener for #{mapping_name}, " +
            "similar one already registred, Info: " + JSON.stringify(info))
      verb.entities[info.entity][info.regex] = info
    else
      # register calls without entity
      # basic check for duplicates
      if verb.flat[info.regex]
        throw new Error("Cannot register listener for #{mapping_name}, " +
            "similar one already registred, Info: " + JSON.stringify(info))
      verb.flat[info.regex] = info

  # build regex for enterprise calls and register to HE help module
  # info: list of the function info:
  #  verb: verb to prerform
  #  entity: entity for verb to operate (optional)
  #  extra: extra regex (after the first 2), default: "[ ]?(.*)?"
  #  type: hear/respond
  #  help: help message for call
  #  example: parameters usage example to be showed in help
  #
  # returns regex:
  #  /#{info.product} #{info.verb} #{info.entity} #{info.extra}/i
  build_enterprise_regex = (info, integration_name) ->
    # backward compatibility for old version (verb vas called action)
    if info.action
      info.verb = info.action
      delete info.action
    info.product = find_alias_by_name(integration_name)
    # do not accept unregistered integrations
    if !registrar.apps[integration_name]
      throw new Error("cannot register listener for #{integration_name}, " +
          "integration #{integration_name} not registered, please use " +
          "robot.e.registerIntegration")
    if !info.verb
      throw new Error("Cannot register listener for #{info.product}, " +
          "no verb passed")
    if info.verb.includes(" ") || (info.entity && info.entity.includes(" "))
      throw new Error("Cannot register listener for #{info.product}, " +
          "verb/entity must be a single word")
    info.regex = build_extra_re(info)
    if !info.type || (info.type != 'hear')
      info.type = 'respond'
    re_string = "#{info.product} #{info.verb}"
    if info.entity
      re_string += " #{info.entity}"
    re_string += "#{info.regex}$"
    registrar_add_call(info, integration_name)
    return new RegExp(re_string, 'i')

  # register integration with hubot-enterprise
  #
  # metadata:
  #  name: (optional) Integration alias (how the chat USER will call it)
  #  short_desc: short description of the integration
  #  long_desc: (optional) long description of the integration
  # authentication:
  #  type: one of the allowed type in auth module, e.g: 'username_password'
  #  options: auth options corresponding to selected auth.type
  robot.e.registerIntegration = (metadata, authentication) ->
    integration_name = find_integration_name()
    if _.includes(reserverd_apps, integration_name)
      throw new Error("integration name cannot have reserved name " +
          integration_name)
    if registrar.apps[integration_name]
      throw new Error("Integration #{integration_name} already registred!")
    if (typeof metadata.name == "string")
      if metadata.name.includes(" ")
        throw new Error("Cannot register integration for " +
            "#{integration_name}, " +
            "name alias must be a single word")
      else if _.includes(reserverd_apps, metadata.name)
        throw new Error("integration metadata.name cannot have reserved name " +
            metadata.name)
      else
        registrar.mapping[metadata.name] = integration_name
    else if _.includes(Object.keys(metadata), 'name')
      throw new Error("Cannot register integration for #{integration_name}, " +
          "name alias must be a string")
    else
      registrar.mapping[integration_name] = integration_name
    # check input
    if !metadata.short_desc
      throw new Error('at least medatada.short_desc must be specified')
    metadata.long_desc = metadata.long_desc || metadata.short_desc

    # Check that auth existing and correct.
    if authentication
      if !auth_client
        throw robot.e.auth.errors.not_enabled

      if !authentication.type
        throw robot.e.auth.errors.no_type

      if !_.includes(robot.e.auth.TYPES, authentication.type)
        throw robot.e.auth.errors.unsupported_type

      validatedAuthentication = robot.e.auth
        .validate_authentication(authentication)

      if validatedAuthentication
        authentication = validatedAuthentication
      else
        throw robot.e.auth.errors.failed_validation

      robot.logger.info "Authentication was enabled for " +
          "integration #{integration_name}"
    else
      robot.logger.info "No authentication method specified for " +
          "#{integration_name} in registration"

    robot.logger.debug "Successfully registerd #{integration_name} with:"
    robot.logger.debug "Meta = #{JSON.stringify(metadata)}"
    robot.logger.debug "Auth = #{JSON.stringify(authentication)}"

    registrar.apps[integration_name] = {
      metadata: metadata,
      auth: authentication || null,
      verbs: {}
    }

  # register a listener function with hubot-enterprise
  #
  # info: list of the function info:
  #  product: product name- OPTIONAL (lib will determin product by itself)
  #  verb: verb to prerform
  #  entity: entity for verb to operate (optional)
  #  type: hear/respond
  #  regex_suffix: (optional) extra element
  #    optional: (optional) true/false- should it be optional
  #    re: (optional) string that representing the regex (optional)
  #  help: help string
  #  example: parameters usage example to be showed in help
  # callback: function to run
  #
  # will register function with the following regex:
  # robot[info.type]
  #  /#{info.product} #{info.verb} #{info.entity} #{info.extra}/i
  robot.e.create = (info, callback) ->
    handler_type = typeof callback
    if handler_type != 'function'
      throw new Error('callback is not a function but a ' + handler_type)
    info.cb = callback
    integration_name = find_integration_name()
    re = build_enterprise_regex(info, integration_name)
    robot.logger.debug("HE registering call:\n" +
        "\trobot.#{info.type} #{re.toString()}")

    # TODO: refactor this into its own function
    authenticated_handler = (msg) ->
      # Execute auth and then handler
      # Execute authentication mechanisms when:
      # * Integration has added authentication configuration, and
      # * The integration listener was flagged
      if !msg.envelope?.user?.id?
        robot.logger.debug('WARNING: username / id is not available for ' +
            'authentication flow')
      cmd = find_alias_by_name(integration_name) + ' ' +
        info.verb + ' ' + info.entity
      auth_client.authenticatedAsync(msg.envelope.user.id,
        find_alias_by_name(integration_name))
        .then (secrets) ->
          # Successfully retrieved secrets
          try
            return callback(msg, secrets, robot)
          # catch error generated BY callback and not by authentication
          catch error
            robot.logger.error('Error executing: ' + cmd + ". {#error}")
        .catch (e) ->
          # Respond according to the type of error
          if _.includes(e.toString(), auth.client.UNEXPECTED_STATUS_CODE) and
             _.includes(e.toString(), '404')
            # The response was NOT_FOUND, therefore need to authenticate.
            token_url_info =
              userInfo:
                id: msg.envelope.user.id
              integrationInfo:
                name: find_alias_by_name(integration_name)
                auth: registrar.apps[integration_name].auth
              botInfo: {}
              urlProps:
                ttl: registrar.apps[integration_name].auth.token_ttl? ||
                  auth.values.DEFAULT_TOKEN_TTL
            robot.logger.debug("Need to authenticate.")
            robot.logger.debug("Generating token_url with payload = " +
                "#{JSON.stringify(token_url_info)}")
            msg.room = "@#{msg.envelope.user.name}"
            msg.reply commons.authentication_announcement(cmd)
            # Request a token_url to send to user.
            auth_client.generateTokenUrlAsync(token_url_info)
            .then (token_response) ->
              # Send token_url to users
              robot.logger.info "Sending #{token_response.url} to #{msg.room}"
              robot.e.adapter.message(msg,
                commons.authentication_message(cmd,token_response.url), true)
            .catch (e) ->
              # Something went wrong, cannot send token_url
              robot.logger.error e
              robot.e.adapter.message(msg,
                commons.authentication_error_message(e), true)
          else
            # Other errors which are not related to not being authenticated.
            # It is good UX to inform user of errors.
            robot.logger.error e
            msg.reply commons.authentication_error_message(e)

    # Authentication is disabled by explicitly specifying auth: false in the
    # robot.e.create() params.
    something = auth_client and registrar.apps[integration_name]?.auth
    if something and info.auth != false
      # If authentication is enabled and integration has registered it
      robot.logger.debug "Adding authentication to robot. " +
          "#{info.type} #{re.toString()}"
      robot[info.type] re, authenticated_handler
    else
      # If no authentication needed, use this handler instead
      robot.logger.debug "No authentication for robot.#{info.type}" +
          "#{re.toString()}"
      robot[info.type] re, (msg) ->
        callback(msg, robot)

  # main receiveMiddleware
  robot.receiveMiddleware (context, next, done) ->
    msg = context.response
    # continues only if its a standart text message event
    if !msg?.message?.text
      return next()
    # process and show help messages
    help.process_help(msg, registrar)
    return next()

  robot.enterprise = robot.e

  # load hubot enterprise scripts (not from integrations) after HE loaded
  load_he_scripts('enterprise_scripts')
