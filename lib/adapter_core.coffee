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


# core of advanced API adapter
# detering which adapter to load
# pass the request if function exists and user allowed to do so

fs = require 'fs'
Promise = require 'bluebird'
adapters_path = __dirname+'/advanced_adapter/adapter-'
table = require 'easy-table'
#list of advanced commands: with elevated permissions
advanced_commands = []

#adapter core class: giving shared api for all adapters+ error handling
class AdapterCore
  constructor: (robot) ->
    @robot = robot
    # try to load specific adapter, if not: make it empty
    try
      fs.accessSync(adapters_path+@robot.adapterName+'.coffee', fs.F_OK)
      @adapter = new (require adapters_path+@robot.adapterName)()
    catch error
      @adapter = {}
  # PLACEHOLDER: check command if its approved for this user
  approve_command: (command, user_info) ->
    return true

  # exec API command:
  # msg: message object hubot
  # command: command name from list of commands
  # params: params for the specific command
  # example (use with bluebird library):
  # return robot.enterprse.adapter.exec(msg, 'listChannels', param, param)
  # .then (res) ->
  #   ...some code...
  #   return robot.enterprse.adapter.exec(msg, 'join', param)
  # .then (res) ->
  #   .. some other code ..
  # .catch (e) ->
  #   ... some error handling code...
  exec: (msg, command, params...) ->
    # this is not binding inside callbacks
    _this = @
    _robot = @robot
    _adapter = @adapter
    return new Promise (resolve, reject) ->
      _robot.logger.debug "Adapter CORE: request to exec #{command} with "+
        "params: {#params}"
      # reject promise  if no adapter (can be cougnt using .catch function)
      if not _adapter[command]
        _robot.logger.debug "command #{command} not available for adapter "+
          _robot.adapterName
        return reject("command #{command} not available for adapter "+
          _robot.adapterName)
      #TODO: extract user_info probably from Auth module
      user_info = {}
      # reject promise if user have no right to make this call
      if not _this.approve_command user_info, command
        _robot.logger.debug "command #{command} not approved for user"
        reject("command #{command} not approved for user")
      else
        # resolve if all ok, use .apply to expand arr of params to function
        resolve(_adapter[command].apply(_adapter, params))
  # table formatter, return formatted table surrounded by platform quotation marks
  # data: can be one of the following:
  #   2d array, when the first is table header
  #   array of key: value objects when the each key will be table header
  # example 2d: getTable([['name', 'email'], ['john', 'john@acme.com'], ...])
  # exemply obj: getTable([{name: 'john', email: 'john@acme.com'}, {name:....}])
  getTable: (data) ->
    t = new table
    quote =
      start: ''
      end: ''
    # set start and end quotes by platform (if any)
    if (@adapter.quote)
      quote.start = @adapter.quote.start || ''
      quote.end = @adapter.quote.end || ''
    if (data[0] instanceof Array)
      # run the array, skip the first because it's the table header
      for el in data.slice(1)
        for i in [0 ... el.length]
          t.cell(data[0][i], el[i])
        t.newRow()
    # TODO: is there any chance in this conditional or within this loop to add
    #   some validation to make sure that the format of
    #   the array items is the one that we expect?
    else
      for el in data
        for key of el
          t.cell(key, el[key])
        t.newRow()
    return quote.start+t.toString()+quote.end

  # advanced message api
  # msg: hubot message object or custom message
  #   To send out of conversation context (when no msg object):
  #   user: username to send to (in case of reply=true)
  #   room: room NAME prefixed by # --or-- username prefixed by @ for DM
  # message: message object to be sent or str (for basic)
  #   text: text message
  #   color: hex color representation or 'good/warning/danger'
  #   title: message title
  #   subtitle: message subtitle
  #   link: url
  #   image: url
  #   footer: string
  #   footer icon: url
  # reply: true/false- reply (assign username prefix) in case of public room
  message: (msg, message, reply) ->
    # initialize opt
    opt =
      user: msg.user
      room: msg.room
      custom_msg: !!msg.room
    # if not custom message, try to get from msg.envelope (fallback to custom)
    if not opt.custom_msg
      if msg.envelope.user
        opt.user = msg.envelope.user.name || opt.user
      opt.room = msg.envelope.room || opt.room
    if @adapter.customMessage
      return @adapter.customMessage(@robot, msg, message, opt, reply)
    return @messageFallback(msg, message, opt, reply)

  # fallback to message: used in case that no adapter or no special message in adapter
  # implements @message api
  messageFallback: (msg, message, opt, reply) ->
    toSend = []
    if opt.custom_msg
      @robot.logger.error 'Cannot send special custom messages '+
        '(robot.e.message), falling back to msg.reply/send'
    if typeof message == 'string'
      toSend = message
    else
      if message.title
        toSend.push(message.title)
      if message.text
        toSend.push(message.text)
      if message.link
        if message.link_desc
          toSend.push(message.link_desc+": "+message.link)
        else
          toSend.push(message.link)
      if message.footer
        toSend.push(message.footer)
      toSend = toSend.join('\n')
    if (reply)
      return msg.reply(toSend)
    return msg.send toSend

module.exports = AdapterCore
