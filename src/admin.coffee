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

# adapter administration script

Promise = require 'bluebird'
module.exports = (robot) ->
  archive = new (require '../lib/archive')(robot)
  _this = @

  archive_channel = (msg, _robot) ->
    if msg.match[1]=='#general'
      msg.reply 'cannot archive #general channel'
      return
    else if msg.match[1]=='this'
      channel = msg.envelope.message.room
    else
      channel = '#'+msg.match[1]
    _robot.logger.debug 'archiving channel: #'+channel
    msg.reply 'Yes sir!'
    archive.archive_channel(msg, channel)
    .catch (e) ->
      _robot.logger.debug e
      msg.reply 'Error: '+e

  archive_older = (msg, _robot) ->
    room = msg.message.room
    type = 'name'
    timeType = msg.match[2].toLowerCase()
    seconds = switch
      when timeType=='d' then msg.match[1]*86400
      when timeType=='h' then msg.match[1]*3600
      when timeType=='m' then msg.match[1]*60
      when timeType=='s' then msg.match[1]
      else
        msg.match[1]
        timeType='s'
    # currently hardcoded patterns
    if (msg.match[3] &&
    (pattern_option = /(named|topic) (.*)/i.exec(msg.match[3])))
      patterns = []
      HUBOT_ADMIN_CHANNEL_MIN = process.env.HUBOT_ADMIN_CHANNEL_MIN || 3
      if pattern_option[1] == 'topic'
        type = 'topic'
      for arg in pattern_option[2].split(process.env.HUBOT_ADMIN_OR || ' or ')
        if arg.length > HUBOT_ADMIN_CHANNEL_MIN
          patterns.push arg
        else
          msg.reply 'Channel prefix "'+arg+'" is too short, '+
              'should be at least '+HUBOT_ADMIN_CHANNEL_MIN+' characters long'
    else
      patterns = ['advantage', 'incident']
    if patterns.length == 0
      msg.reply 'no patterns to archive'
      return
    msg.reply 'archiving channels with pattern: "'+patterns.join('", "')+
      '" older than '+msg.match[1]+timeType+' by '+type
    archive.archive_old(msg, seconds, patterns, room, type)
    .then (response) ->
      _robot.logger.debug "back from Promise {#response}"
      msg.reply 'done, total archived: '+response.totalArchived
    .catch (e) ->
      _robot.logger.debug e
      msg.reply 'Error: '+e

  # register module
  robot.e.registerIntegration({short_desc: "Admin module for hubot enterprise",
  long_desc: "Admin module contain number of calls for Chat platform "+
  "managing", name: "admin"})
  # register hubot enterprise functions
  robot.e.create {verb: 'archive', entity: 'channel',
  example: '#channelName', type: 'respond',
  help: '<this|#name>- archive specific channel'},
  archive_channel

  robot.e.create {verb: 'archive', entity: 'older', example: '5d',
  regex_suffix: {re: "([0-9]+)([dDhHmMsS]) ?(.*)", optional: false},
  help: '<N>(D/H/M/S) (named|tag) <name|tag> or <name|tag>- '+
  'archive channels older than by name or by topic', type: 'respond'},
  archive_older
