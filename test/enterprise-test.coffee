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


Helper = require('hubot-test-helper')
chai = require 'chai'
extend = require('util')._extend

expect = chai.expect

helper = new Helper('../src/0_bootstrap.coffee')

describe 'basic enterprise tests', ->
  beforeEach ->
    @room = helper.createRoom()
    @room.robot.e.registerIntegration({
      short_desc: 'hubot-enterprise administration functions', name: 'test'})
    @room.robot.e.create {verb: 'update', entity: 'ticket'
    help: 'update ticket', type: 'respond'}, (msg)->
      msg.reply 'in test update ticket'
    @room.robot.e.create {verb: 'read', entity: 'issue'
    help: 'read ticket', type: 'hear'}, (msg)->
      msg.reply 'in test read issue'
    @room.robot.e.create {verb: 'read', entity: 'list'
    help: 'read ticket', type: 'respond'}, (msg)->
      msg.reply 'in test read ticket'

  afterEach ->
    @room.destroy()

  it 'register respond function', ->
    @room.user.say('alice', '@hubot test update ticket').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot test update ticket' ],
        [ 'hubot', '@alice in test update ticket' ]
      ]

  it 'register hear function', ->
    @room.user.say('alice', 'test read issue jj').then =>
      expect(@room.messages).to.eql [
        [ 'alice', 'test read issue jj' ],
        [ 'hubot', '@alice in test read issue' ]
      ]

  it 'register default listener option (respond)', ->
    @room.robot.e.create {verb: 'read',
    help: 'read ticket'}, (msg)->
      msg.reply 'in test read'
    @room.user.say('alice', '@hubot test read jj').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot test read jj' ],
        [ 'hubot', '@alice in test read' ]
      ]

  it 'verb should exist', ->
    err = 'none'
    try
      @room.robot.enterprise.create {
      entity: 'ticket', help: 'read ticket', type: 'respond'}, (msg)->
        msg.reply 'in foo2 read ticket'
    catch error
      err = error.message
    expect(err).to.eql('Cannot register listener for test, no verb passed')

  it 'verb should not contain spaces', ->
    err = 'none'
    try
      @room.robot.enterprise.create {verb: 'with space'
      entity: 'ticket', help: 'read ticket', type: 'respond'}, (msg)->
        msg.reply 'in foo2 read ticket'
    catch error
      err = error.message
    expect(err).to.eql('Cannot register listener for test, verb/entity must '+
      'be a single word')

  it 'entity should not contain spaces', ->
    err = 'none'
    try
      @room.robot.enterprise.create {verb: 'with'
      entity: 'with space', help: 'read ticket', type: 'respond'}, (msg)->
        msg.reply 'in foo2 read ticket'
    catch error
      err = error.message
    expect(err).to.eql('Cannot register listener for test, verb/entity must '+
      'be a single word')

  # test for backward compatibility robot.enterprise -> robot.e
  it 'check backward compatibility for robot.enterprise', ->
    @room.robot.enterprise.create {verb: 'read',
    entity: 'ticket', help: 'read ticket', type: 'respond'}, (msg)->
      msg.reply 'in test read ticket'
    @room.user.say('alice', '@hubot test read ticket').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot test read ticket' ],
        [ 'hubot', '@alice in test read ticket' ]
      ]

  # test backward compatibility for call set {product, action}
  it 'check backward compatibility for {product, action}', ->
    @room.robot.e.create {action: 'read',
    help: 'read ticket', type: 'respond'}, (msg)->
      msg.reply 'in test read'
    @room.user.say('alice', '@hubot test read').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot test read' ],
        [ 'hubot', '@alice in test read' ]
      ]

describe 'help tests', ->

  cb = (msg) ->
    msg.reply 'here'

  beforeEach ->
    @room = helper.createRoom()
    @room.robot.e.registerIntegration({name: 'test',
    short_desc: 'short tests desc', long_desc: 'long tests desc'})

    @room.robot.e.create {action: 'read',
    help: 'read ticket', type: 'respond'}, cb

    @room.robot.e.create {action: 'read', entity: 'me'
    regex_suffix: {re: "aa (.*)", optional: false},
    example: "aa hello world",
    help: 'read ticket', type: 'respond'}, cb

    @room.robot.e.create {action: 'read-all', entity: 'me'
    regex_suffix: {re: "aa (.*)", optional: false},
    example: "aa hello world",
    help: 'read everything', type: 'respond'}, cb

    @room.robot.e.create {action: 'create', entity: 'ticket',
    regex_suffix: {optional: false}, help: 'help 1'}, cb

    @room.robot.e.create {action: 'delete', entity: 'ticket',
    regex_suffix: {re: "hello (.*)", optional: true}, help: 'help 2'}, cb

    @room.robot.e.create {action: 'delete', entity: 'ticket',
    regex_suffix: {re: "world (.*)", optional: true}, help: 'help 2_w'}, cb

    @room.robot.e.create {action: 'delete', regex_suffix: {optional: false}}, cb

    @room.robot.e.create {action: 'delete', entity: 'issue',
    regex_suffix: {optional: false}, help: 'help 3'}, cb

  afterEach ->
    @room.destroy()

  it 'help general', ->
    @room.user.say('alice', '@hubot help').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'Enterprise integrations list:\n'+
        '\t-test: short tests desc\n'+
        '\nHubot help:\n' ]
      ]

  it 'help integration', ->
    @room.user.say('alice', '@hubot help test').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        '*test* Integration: short tests desc\n'+
        '- *Verbs:* read, read-all, create, delete\n'+
        '- *Description:*\n'+
        'long tests desc\n' ]
      ]

  it 'help verb', ->
    @room.user.say('alice', '@hubot help test delete').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test delete' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'calls for *test delete*\n'+
        '- *Entities*: ticket, issue\n'+
        '- *Calls: *\n'+
        '\t- hubot test delete\n' ]
      ]

  it 'help entity', ->
    @room.user.say('alice', '@hubot help test delete ticket').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test delete ticket' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'calls for *test delete ticket*\n'+
        '\t- hubot test delete ticket(?: hello (.*))?: help 2\n'+
        '\t- hubot test delete ticket(?: world (.*))?: help 2_w\n' ]
      ]

  it 'help n/a itegration', ->
    @room.user.say('alice', '@hubot help cow').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help cow' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'there is no such integration *cow*\n'+
        'Enterprise integrations list:\n'+
        '\t-test: short tests desc\n'+
        '\nHubot help:\n' ]
      ]

  it 'help n/a verb', ->
    @room.user.say('alice', '@hubot help test remove dog').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test remove dog' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'there is no such verb *remove* for integration *test*\n'+
        '*test* Integration: short tests desc\n'+
        '- *Verbs:* read, read-all, create, delete\n'+
        '- *Description:*\n'+
        'long tests desc\n' ]
      ]

  it 'help n/a entity', ->
    @room.user.say('alice', '@hubot help test delete cat').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test delete cat' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'there is no such entity *cat* for verb *delete* of *test*\n'+
        'calls for *test delete*\n'+
        '- *Entities*: ticket, issue\n'+
        '- *Calls: *\n'+
        '\t- hubot test delete\n' ]
      ]


  it 'help respond to `enterprise` keyword', ->
    @room.user.say('alice', '@hubot enterprise').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot enterprise' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'Enterprise integrations list:\n'+
        '\t-test: short tests desc\n'+
        '\nHubot help:\n' ]
      ]

  it 'help respond to `?` keyword', ->
    @room.user.say('alice', '@hubot ?').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot ?' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'Enterprise integrations list:\n'+
        '\t-test: short tests desc\n'+
        '\nHubot help:\n' ]
      ]

  it 'help show example', ->
    @room.user.say('alice', '@hubot ? test read me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot ? test read me' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'calls for *test read me*\n'+
        '\t- hubot test read me aa hello world: read ticket\n' ]
      ]

  it 'help show fuzzy match', ->
    @room.user.say('alice', '@hubot help test delere').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help test delere' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'there is no such verb *delere* for integration *test*, '+
        'did you mean *delete*?\n'+
        '*test* Integration: short tests desc\n'+
        '- *Verbs:* read, read-all, create, delete\n'+
        '- *Description:*\n'+
        'long tests desc\n' ]
      ]
  it 'help with command that include a dash', ->
    @room.user.say('bob', '@hubot help test read-all').then =>
      expect(@room.messages).to.eql [
        ['bob', '@hubot help test read-all']
        ['hubot', '@bob help for hubot enterprise:\n'+
        'calls for *test read-all*\n'+
        '- *Entities*: me\n']
      ]
  it 'help with non-existent command that include a dash', ->
    @room.user.say('bob', '@hubot help test read-most').then =>
      expect(@room.messages).to.eql [
        ['bob', '@hubot help test read-most']
        ['hubot', '@bob help for hubot enterprise:\n'+
        'there is no such verb *read-most* for integration *test*\n'+
        '*test* Integration: short tests desc\n'+
        '- *Verbs:* read, read-all, create, delete\n'+
        '- *Description:*\n'+
        'long tests desc\n']
      ]

describe 'registerIntegration tests', ->

  cb = (msg) ->
    msg.reply "here"
  beforeEach ->
    @room = helper.createRoom()

  afterEach ->
    @room.destroy()

  it 'cannot call robot.e.create() without robot.e.registerIntegration()', ->
    err = 'none'
    try
      @room.robot.e.create {verb: 'update', entity: 'ticket'
      help: 'update ticket', type: 'respond'}, (msg)->
        msg.reply 'in test update ticket'
    catch error
      err = error.message
    expect(err).to.eql('cannot register listener for enterprise, integration '+
      'enterprise not registered, please use robot.e.registerIntegration')

  # disabled untill keyword for help will be changed from `enterprise`
  it 'register integration: name auto discover', ->
    # @room.robot.e.registerIntegration({short_desc: 'short tests desc',
    # long_desc: 'long tests desc'})

    # @room.robot.e.create {action: 'read', help: 'read ticket', type: 'respond'},
    #   cb
    #
    # @room.user.say('alice', '@hubot help read').then =>
    #   expect(@room.messages).to.eql [
    #     [ 'alice', '@hubot help read' ],
    #     [ 'hubot', '@alice here' ]
    #   ]

  it 'register integration custom name', ->
    @room.robot.e.registerIntegration({name: 'test',
    short_desc: 'short tests desc', long_desc: 'long tests desc'})

    @room.robot.e.create {action: 'read', help: 'read ticket', type: 'respond'},
     cb

    @room.user.say('alice', '@hubot test read').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot test read' ],
        [ 'hubot', '@alice here' ]
      ]

  it 'cannot register integration twice', ->
    @room.robot.e.registerIntegration({short_desc: 'short tests desc',
    long_desc: 'long tests desc'})

    err = 'none'
    try
      @room.robot.e.registerIntegration({short_desc: 'short tests desc',
      long_desc: 'long tests desc'})
    catch error
      err = error.message
    expect(err).to.eql('Integration enterprise already registred!')

  it 'cannot register integration twice even under another name', ->
    @room.robot.e.registerIntegration({name: 'test',
    short_desc: 'short tests desc', long_desc: 'long tests desc'})

    err = 'none'
    try
      @room.robot.e.registerIntegration({name: 'test2',
      short_desc: 'short tests desc', long_desc: 'long tests desc'})
    catch error
      err = error.message
    expect(err).to.eql('Integration enterprise already registred!')

  it 'name must be single word', ->
    err = 'none'
    try
      @room.robot.e.registerIntegration({name: 'test2 hh',
      short_desc: 'short tests desc', long_desc: 'long tests desc'})
    catch error
      err = error.message
    expect(err).to.eql('Cannot register integration for enterprise, '+
    'name alias must be a single word')

  it 'name must be a string', ->
    err = 'none'
    try
      @room.robot.e.registerIntegration({name: true,
      short_desc: 'short tests desc', long_desc: 'long tests desc'})
    catch error
      err = error.message
    expect(err).to.eql('Cannot register integration for enterprise, '+
      'name alias must be a string')

  it 'short_desc is mandatory', ->
    it 'name must be single word', ->
      err = 'none'
      try
        @room.robot.e.registerIntegration({name: 'test2 hh',
        long_desc: 'long tests desc'})
      catch error
        err = error.message
      expect(err).to.eql('Cannot register a listener, info.regex_suffix.re '+
        'must be a string or undefined')

  it 'long desc is optional, if not exists: assigning short desc', ->
    @room.robot.e.registerIntegration({name: 'test',
    short_desc: 'short tests desc'})
    @room.user.say('alice', '@hubot help').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot help' ],
        [ 'hubot', '@alice help for hubot enterprise:\n'+
        'Enterprise integrations list:\n'+
        '\t-test: short tests desc\n'+
        '\nHubot help:\n' ]
      ]

  it 'cannot register integration with reserved name', ->
    err = 'none'
    try
      @room.robot.e.registerIntegration({name: 'info',
      short_desc: 'short tests desc', long_desc: 'long tests desc'})
    catch error
      err = error.message
    expect(err).to.eql('integration metadata.name cannot have '+
      'reserved name info')

describe 'listener extra object tests', ->

  callback = (msg) ->
    if msg.match[1]
      msg.reply "#{msg.match[1]}"
    else
      msg.reply "NONE"

  beforeEach ->
    @room = helper.createRoom()
    @room.robot.e.registerIntegration({name: 'foo', short_desc: 'suffix tests'})

  # common create object, to extend
  common_create = { verb: 'verb', entity: 'entity'}

  afterEach ->
    @room.destroy()

  it 'regex_suffix: regex, optional: true- call with suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: true}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice me' ]
      ]

  it 'regex_suffix: regex, optional: true- call w/o suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: true}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity' ],
        [ 'hubot', '@alice NONE' ]
      ]

  it 'regex_suffix: regex, optional: true- call witout space between entity '+
  'and suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: true}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entitywith me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entitywith me' ]
      ]

  it 'regex_suffix, regex, optional: false- call with suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: false}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice me' ]
      ]
  it 'regex_suffix, regex, optional: false- call witout space between entity '+
  'and suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: false}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entitywith me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entitywith me' ]
      ]

  it 'regex_suffix, regex, optional: false- call without suffix', ->
    call = extend({regex_suffix: {re: 'with (.*)', optional: false}},
      common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity' ]
      ]

  it 'regex_suffix, no regex, optional: true- call with suffix', ->
    call = extend({regex_suffix: {optional: true}}, common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice with me' ]
      ]

  it 'regex_suffix, no regex, optional: false- call with suffix', ->
    call = extend({regex_suffix: {optional: false}}, common_create)
    @room.robot.e.create call, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ]
      ]

    it 'regex_suffix, no regex, optional: false- call without suffix', ->
      call = extend({regex_suffix: {optional: false}}, common_create)
      @room.robot.e.create call, callback
      @room.user.say('alice', '@hubot foo verb entity').then =>
        expect(@room.messages).to.eql [
          [ 'alice', '@hubot foo verb entity with me' ],
          [ 'hubot', '@alice NONE' ]
        ]

  it 'no regex_suffix object- call with suffix', ->
    @room.robot.e.create common_create, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice with me' ]
      ]

  it 'regex_suffix is null- call with suffix', ->
    common_create.regex_suffix = null
    @room.robot.e.create common_create, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice with me' ]
      ]

  it 'regex_suffix.re is not a string', ->
    common_create.regex_suffix = {re: true}
    err = 'none'
    try
      @room.robot.e.create common_create, callback
    catch error
      err = error.message
    expect(err).to.eql('Cannot register a listener, info.regex_suffix.re '+
      'must be a string or undefined')

  it 'regex_suffix.optional is not boolean', ->
    common_create.regex_suffix = {optional: "hello"}
    err = 'none'
    try
      @room.robot.e.create common_create, callback
    catch error
      err = error.message
    expect(err).to.eql('Cannot register a listener, '+
    'info.regex_suffix.optional must be a boolean or undefined')

  it 'no regex_suffix boject- call without suffix', ->
    delete common_create.regex_suffix
    @room.robot.e.create common_create, callback
    @room.user.say('alice', '@hubot foo verb entity').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity' ],
        [ 'hubot', '@alice NONE' ]
      ]

  it 'regex suffix is not an object', ->
    common_create.regex_suffix = true
    err = 'none'
    try
      @room.robot.e.create common_create, callback
    catch error
      err = error.message
    expect(err).to.eql('info.regex_suffix MUST be an object')


  it 'extra passed as string (backward compatibility)- call with suffix', ->
    common_create.extra = "with (.*)"
    delete common_create.regex_suffix
    @room.robot.e.create common_create, callback
    @room.user.say('alice', '@hubot foo verb entity with me').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity with me' ],
        [ 'hubot', '@alice me' ]
      ]

  it 'extra passed as string (backward compatibility)- call without suffix', ->
    common_create.extra = "with (.*)"
    delete common_create.regex_suffix
    @room.robot.e.create common_create, callback
    @room.user.say('alice', '@hubot foo verb entity').then =>
      expect(@room.messages).to.eql [
        [ 'alice', '@hubot foo verb entity' ]
      ]
