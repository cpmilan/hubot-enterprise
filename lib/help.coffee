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

_ = require 'lodash'
Matcher = require 'did-you-mean'
class Help

  # constructor for help
  #  robot: hubot robot object
  #  help_words: help key-words array
  constructor: (robot, help_words) ->
    @robot = robot
    @commons = new (require __dirname+'/../lib/commons')()
    @help_words = help_words
  # give best matched word
  #
  #  words_arr: array of words to match from
  #  word: word to match
  #  threshold: minimal score to show (levenshtein algorythm threshold)
  #
  fuzzy_match: (words_arr, word, threshold = 2) ->
    # Create a matcher with a list of values
    matcher = new Matcher(words_arr.join(' ')).setThreshold(threshold)
    .ignoreCase()
    # Get the closest match
    if (word = matcher.get(word))
      return @commons.did_you_mean(word)
    else
      return ''

  # process help and show message (accept hubot middleware)
  #  msg: hubot message object (context.response)
  #  registrar: HE registrar object
  process_help: (msg, registrar) ->
    # build help regex from help workds array
    help_re = @robot.respondPattern(new RegExp("("+@help_words.join('|')+")"+
      "[ ]?([a-zA-Z\\-]+)?[ ]?([a-zA-Z\\-]+)?[ ]?([a-zA-Z\\-]+)?", 'i'))
    if (msg.match = msg.message.text.match(help_re))
      help = @show_help(registrar, msg.match[2], msg.match[3], msg.match[4])
      @robot.logger.debug help
      @robot.logger.debug 'msg.message.text: '+msg.message.text
      # if found integration: display only HE help
      if (help.found_app == true)
        @robot.logger.debug 'Help: KILL MESSAGE CHAIN'
        msg.message.finish()
      else
        # changing current keyword to help: for hubot-help to work
        msg.message.text = msg.message.text.replace(msg.match[1], 'help')
        help.text = help.text+"\nHubot help:\n"
      @robot.logger.debug 'Showing enterprise help'
      msg.reply @commons.help_msg(help.text)

  # return enterprise help as string
  #
  # registrar: HE registrar object
  # product: product (or alias)
  # verb: verb
  # entity: entity
  #
  show_help: (registrar, product, verb, entity) ->
    # TODO: use Cha to display
    # TODO: refactor based on UI/UX team specs
    res =
      text: ""
      found_app: false
    if product
      if !registrar.mapping[product] ||
      !registrar.apps[registrar.mapping[product]]
        res.text = @commons.no_such_integration(product)+
          @fuzzy_match(Object.keys(registrar.mapping), product)+"\n"+
          @show_help(registrar).text
      else
        res.found_app = true
        reg_product = registrar.apps[registrar.mapping[product]]
        if verb
          if !reg_product.verbs[verb]
            res.text = @commons.no_such_verb(product, verb)+
              @fuzzy_match(Object.keys(reg_product.verbs), verb)+"\n"+
              @show_help(registrar, product).text
          else
            reg_verb = reg_product.verbs[verb]
            if entity
              if !reg_verb.entities[entity]
                res.text = @commons.no_such_entity(product, verb, entity)+
                  @fuzzy_match(Object.keys(reg_verb.entities), entity)+"\n"+
                  @show_help(registrar, product, verb).text
              else
                res.text = "calls for *#{product} #{verb} #{entity}*\n"
                for k, v of reg_verb.entities[entity]
                  res.text += "\t- "
                  if v.type == 'respond'
                    res.text += "#{@robot.name} "
                  res.text +="#{product} #{verb} #{entity}"+
                  (if v.example then " #{v.example}" else k)+
                  (if v.help then ': '+v.help else '')+"\n"
            else
              res.text += "calls for *#{product} #{verb}*\n"
              entities = Object.keys(reg_verb.entities)
              flat = Object.keys(reg_verb.flat)
              if entities.length > 0
                res.text += "- *Entities*: "+entities.join(', ')+"\n"
              if flat.length > 0
                res.text += "- *Calls: *\n"
                for k, v of reg_verb.flat
                  res.text += "\t- "
                  if v.type == 'respond'
                    res.text += "#{@robot.name} "
                  res.text +="#{product} #{verb}"+
                    (if v.example then " #{v.example}" else k)+
                    (if v.help then ': '+v.help else '')+"\n"
        else
          vrbs = Object.keys(reg_product.verbs).join(', ')
          res.text += "*#{product}* Integration: "+
            "#{reg_product.metadata.short_desc}\n- *Verbs:* #{vrbs}\n"+
            "- *Description:*\n#{reg_product.metadata.long_desc}\n"
    else
      res.text += "Enterprise integrations list:\n"
      for alias, app of registrar.mapping
        res.text +=
          "\t-#{alias}: #{registrar.apps[app].metadata.short_desc}\n"
    return res

module.exports = Help
