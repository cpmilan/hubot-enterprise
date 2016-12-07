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

# change log level to eliminate hubot warning about copoyright style

Helper = require('hubot-test-helper')
chai = require 'chai'

expect = chai.expect

helper = new Helper('../src')

describe 'hubot-admin tests', ->
  beforeEach ->
    @room = helper.createRoom()

  afterEach ->
    @room.destroy()

  it 'admin archive older 5s', ->
    this.timeout(8000)
    @room.user.say('alice', '@hubot admin archive older 5s').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot admin archive older 5s' ],
        [ 'hubot', '@alice archiving channels with pattern: "advantage", '+
          '"incident" older than 5s by name' ],
        ['hubot', '@alice Error: command channelList not available for '+
          'adapter null']
      ]

  it 'admin archive older 5s named JJ or BB or DDDD', ->
    @room.user.say('alice', '@hubot admin archive older 5s named JJ or BB or '+
    'DDDD').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot admin archive older 5s topic JJ or BB or DDDD' ],
        [ 'hubot', '@alice Channel prefix "JJ" is too short, should be at '+
          'least 3 characters long' ],
        [ 'hubot', '@alice Channel prefix "BB" is too short, should be at '+
          'least 3 characters long' ],
        [ 'hubot', '@alice archiving channels with pattern: "DDDD" older '+
          'than 5s by name' ]
      ]

    it 'admin archive older 5s topic JJ or BB or DDDD', ->
      @room.user.say('alice', '@hubot admin archive older 5s topic BBBB'+
      ' or DDDD').then =>
        expect(@room.messages).to.eql [
          [ 'alice', '@hubot admin archive older 5s topic BBBB or DDDD' ],
          [ 'hubot', '@alice archiving channels with pattern: "BBBB", "DDDD" '+
            'older than 5s by topic' ]
        ]

  it 'admin archive #general channel', ->
    @room.user.say('alice', '@hubot admin archive channel #general').then =>
      expect(@room.messages).to.eql [
        ['alice', '@hubot admin archive channel #general']
        ['hubot', '@alice cannot archive #general channel']
      ]

  it 'admin archive #some channel', ->
    @room.user.say('bob', '@hubot admin archive channel #some').then =>
      expect(@room.messages).to.eql [
        ['bob', '@hubot admin archive channel #some']
        ['hubot', '@bob Yes sir!']
        ['hubot', '@bob Error: command channelInfo not available '+
          'for adapter null']
      ]
