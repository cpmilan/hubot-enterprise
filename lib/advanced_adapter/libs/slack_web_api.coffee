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

# Copied from Botkit
# api wrapper for slack

request = require 'request'
_ = require('lodash')
Promise = require 'bluebird'

slack_api =
  api_url: 'https://slack.com/api/'
  callAPI: (command, options) ->
    # reject if no token provided
    if not options.token
      return Promise.reject('No token provided, please provide a '+
        'token in SLACK_APP_TOKEN')
    new Promise (resolve, reject)->
      request.post(slack_api.api_url + command, form: options,
      (err, reponse, body)->
        if not err and reponse.statusCode == 200
          json = JSON.parse(body)
          reject(json.error) unless json.ok
          resolve(json)
        else
          reject(err)
      )

  auth:
    test: (options)->
      slack_api.callAPI('auth.test', options)

  oauth:
    access: (options)->
      slack_api.callAPI('oauth.access', options)

  channels:
    archive:(options)->
      slack_api.callAPI('channels.archive', options)

    create: (options)->
      slack_api.callAPI('channels.create', options)

    history: (options)->
      slack_api.callAPI('channels.history', options)

    info: (options)->
      slack_api.callAPI('channels.info', options)

    invite: (options)->
      slack_api.callAPI('channels.invite', options)

    join: (options)->
      slack_api.callAPI('channels.join', options)

    kick:(options)->
      slack_api.callAPI('channels.kick',options)

    leave: (options)->
      slack_api.callAPI('channels.leave',options)

    list: (options) ->
      slack_api.callAPI('channels.list', options)

    mark: (options) ->
      slack_api.callAPI('channels.mark',options)

    rename: (options) ->
      slack_api.callAPI('channels.rename',options)

    setPurpose:(options)->
      slack_api.callAPI('channels.setPurpose',options)

    setTopic:(options)->
      slack_api.callAPI('channels.setTopic', options)

    unarchive: (options)->
      slack_api.callAPI('channels.unarchive', options)

  chat:
    delete: (options)->
      slack_api.callAPI('chat.delete', options)

    postMessage: (options)->
      if (options.attachments and typeof(options.attachments) != 'string')
        options.attachments = JSON.stringify(options.attachments)
      slack_api.callAPI('chat.postMessage', options)

    update: (options)->
      slack_api.callAPI("chat.update",options)

  emoji:
    list: (options) ->
      slack_api.callAPI('emoji.list', options)

  files:
    delete: (options)->
      slack_api.callAPI('files.delete', options)

    info: (options)->
      slack_api.callAPI('files.info', options)

    list: (options)->
      slack_api.callAPI('files.list', options)

    upload: (options)->
      slack_api.callAPI('files.upload', options)

  groups:
    archive: (options)->
      slack_api.callAPI('groups.archive',options)

    close: (options) ->
      slack_api.callAPI('groups.close',options)

    create: (options) ->
      slack_api.callAPI('groups.create',options)

    createChild: (options) ->
      slack_api.callAPI('groups.createChild',options)

    history: (options) ->
      slack_api.callAPI('groups.history',options)

    info: (options) ->
      slack_api.callAPI('groups.info',options)

    invite: (options) ->
      slack_api.callAPI('groups.invite',options)

    kick: (options) ->
      slack_api.callAPI('groups.kick',options)

    leave: (options) ->
      slack_api.callAPI('groups.leave',options)

    list: (options) ->
      slack_api.callAPI('groups.list',options)

    mark: (options) ->
      slack_api.callAPI('groups.mark',options)

    open: (options) ->
      slack_api.callAPI('groups.open',options)

    rename: (options) ->
      slack_api.callAPI('groups.rename',options)

    setPurpose: (options) ->
      slack_api.callAPI('groups.setPurpose',options)

    setTopic: (options) ->
      slack_api.callAPI('groups.setTopic',options)

    unarchive: (options) ->
      slack_api.callAPI('groups.unarchive',options)

  im:
    close: (options)->
      slack_api.callAPI('im.close', options)

    history: (options)->
      slack_api.callAPI('im.history', options)

    list: (options)->
      slack_api.callAPI('im.list', options)

    mark: (options)->
      slack_api.callAPI('im.mark', options)

    open: (options)->
      slack_api.callAPI('im.open', options)

  mpim:
    close: (options) ->
      slack_api.callAPI('mpim.close', options)

    history: (options) ->
      slack_api.callAPI('mpim.history', options)

    list: (options)->
      slack_api.callAPI('mpim.list', options)

    mark: (options)->
      slack_api.callAPI('mpim.mark', options)

    open: (options)->
      slack_api.callAPI('mpim.open', options)

  pins:
    add: (options)->
      slack_api.callAPI('pins.add', options)

    list: (options) ->
      slack_api.callAPI('pins.list', options)

    remove:  (options) ->
      slack_api.callAPI('pins.remove', options)

  reactions:
    add: (options) ->
      slack_api.callAPI('reactions.add', options)

    get: (options) ->
      slack_api.callAPI('reactions.get', options)

    list: (options) ->
      slack_api.callAPI('reactions.list', options)

    remove: (options) ->
      slack_api.callAPI('reactions.remove', options)

  rtm:
    start: (options) ->
      slack_api.callAPI('rtm.start', options)

  search:
    all: (options) ->
      slack_api.callAPI('search.all', options)

    files: (options) ->
      slack_api.callAPI('search.files', options)

    messages: (options) ->
      slack_api.callAPI('search.messages', options)

  stars:
    list: (options) ->
      slack_api.callAPI('stars.list', options)

  team:
    accessLogs: (options)->
      slack_api.callAPI('team.accessLogs', options)

    info: (options)->
      slack_api.callAPI('team.info', options)

  users:
    getPresence: (options) ->
      slack_api.callAPI('users.getPresence',options)

    info: (options) ->
      slack_api.callAPI('users.info',options)

    list: (options) ->
      slack_api.callAPI('users.list',options)

    setActive: (options) ->
      slack_api.callAPI('users.setActive',options)

    setPresence: (options) ->
      slack_api.callAPI('users.setPresence',options)

# Example:
#   options =
#     token: 'xoxp-25470835060-....'
#   api = require 'slack_web_api'
#   api.channels.list(options).then((v)-> console.log v)
module.exports = slack_api
