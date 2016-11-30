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


#AdminExt = require './admin-slack'
Promise = require 'bluebird'
moment = require 'moment'
ARCH_PREFIX = 'ARCH-'
#adapter = new AdminExt()

class Archive
  constructor: (robot) ->
    @adapter = robot.e.adapter
    @robot = robot

  sort_channels: (msg, channels, current, regex, type) ->
    ret = []
    type = type || 'name'
    for channel in channels
      to_test = if (type == 'name') then channel.name else channel.topic
      if regex.test(to_test) && channel.name!=current
        @robot.logger.debug to_test
        ret.push channel
    return ret

  archive_single: (msg, channel) ->
    _adapter = @adapter
    _robot = @robot
    @robot.logger.debug channel
    @robot.logger.debug 'joining'
    return _adapter.exec(msg, 'join', channel.name)
    .then (res) ->
      _robot.logger.debug 'join: ' + res + ', -> setTopic'
      return _adapter.exec(msg, 'setTopic', channel.id, channel.name)
      .then (res) ->
        _robot.logger.debug 'setTopic: '+res+' , -> archive'
        return _adapter.exec(msg, 'archive', channel.id)
      .then (res) ->
        _robot.logger.debug 'archive: '+res+', -> rename'
        return _adapter.exec(msg, 'rename', channel.id, ARCH_PREFIX+Date.now())
      .then (res) ->
        _robot.logger.debug 'rename: '+res+', -> BACK'
        msg.reply 'archived channel: '+channel.name+' ('+channel.id+'), '+
            'created '+moment(channel.created*1000).fromNow()
        return channel.name

  archive_channel: (msg, channel) ->
    _adapter = @adapter
    _this = this
    @robot.logger.debug "in archive channel"
    return _adapter.exec(msg, 'channelInfo', channel)
    .then (res) ->
      return _this.archive_single(msg, res)

  archive_old: (msg, seconds, patterns, thisChannel, type) ->
    _this = this
    totalArchived = 0
    _robot = @robot
    type = type || 'name'
    channelPatterns = new RegExp('('+(patterns.join '|')+')', 'i')
    now = Math.floor(Date.now()/1000)
    _robot.logger.debug 'Archiving older than :'+seconds+' seconds'
    return @adapter.exec(msg, 'channelList', true)
    .then (res) ->
      channels = _this.sort_channels(msg, res, thisChannel, channelPatterns,
        type)
      return Promise.map(channels, (channel) ->
        create_time = now - channel.created
        _robot.logger.debug 'Channel: '+channel.name+' Create elapsed time: '+
          create_time+' created time: '+channel.created
        if create_time > seconds
          _robot.logger.debug 'archiving '+channel.name+' '+channel.id+
            ' ('+create_time+')'
          return _this.archive_single(msg, channel)
          .then (res) ->
            totalArchived++
            return res
      )
      .then (res) ->
        _robot.logger.debug 'MAP DONE'
        res.totalArchived = totalArchived
        return res
      .catch (err) ->
        _robot.logger.debug 'ERROR:'+err
        err.totalArchived = totalArchived
        return err
module.exports = Archive
