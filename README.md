# hubot-enterprise

Hubot middleware and scripts for enterprise

This hubot plugins package created to allow quickly enable multiplatform hubot plugins development and deployment with built in 
security flows, help mechanism, standartized user experience in terms of syntax, message templating and collaboration platforms management API adapters.

## Installation

The package can quickly be deployed and installed using docker with the following prerequisites:
- docker- recommended version: 1.12. [install docker](https://docs.docker.com/engine/installation/).

The [docker image](Dockerfile) includes:
  - nodejs 4 image: [node:4](https://hub.docker.com/r/library/node/) docker image.
  - [yoeman](http://yeoman.io/).
  - [coffee-script](http://coffeescript.org/).
  - [generator-hubot-enterprise](https://github.com/eedevops/generator-hubot-enterprise) which is a fork of [genarator-hubot](https://github.com/github/generator-hubot).

### Running Hubot Enterprise via docker
 
- `docker pull chatopshpe/hubot-enterprise`
- if using slack: [set up slack](#slack-web-api-token-generation)
- run docker:
  ```bash
  docker run \
     -p 8080:8080 \
     -v <integrations_on_disk>:/integration \
     -e "NPM_INTEGRATIONS=<integration to install from npm>" \
     -e "http_proxy=${http_proxy}" \
     -e "https_proxy=${https_proxy}" \
     -e "no_proxy=${no_proxy}" \
     -e "ADAPTER=slack" \
     -e "HUBOT_LOG_LEVEL=info" \
     -e "SLACK_APP_TOKEN=xxxxxxxxx" \
     -e "HUBOT_SLACK_TOKEN=xxxxxxxxxxx" \
     chatopshpe/hubot-enterprise
  ```
  - **integrations_on_disk**: hubot integrations that located in the specified folder.

    this folder may **BE** an integration or **CONTAIN** number of integration folders (named with `hubot-` prefix).

    examples:

    - `/opt/myIntegration/`: may be a project and contain `package.json` file and all rest project structure.
    - `/opt/myIntegrations`: may contain number of folders that contains integrations like and prefixed with `hubot-`.

  - **NPM_INTEGRATIONS**: list of hubot integrations to be installed using npm.
  
  - **ADAPTER**: default is `slack`, here can specify any other adapter to be installed via npm and used by hubot.
    - When replacing adapter, Please check and add all environment variable associated to it.
	  -Sample values: `flowdock`, `hipchat`.

 - **HUBOT_LOG_LEVEL**: level for hubot logger, default `info` optional values: `debug`|`info`|`error`
 - Run as daemon by adding `-d` after the `docker run`.
 
- [using Hubot Enterprise with integration](#using-hubot-enterprise-with-integration)

### Other installation methods

**Creating your new bot**

- `npm install -g coffee-script yo eedevops/generator-hubot-enterprise`
- `mkdir /path/to/hubot/`
- `cd /path/to/hubot`
- `yo hubot-enterprise`

**adding hubot enterprise to existing bot**

- `cd /path/to/hubot/`
- `npm install --save eedevops/hubot-enterprise`
- Add **hubot-enterprise** to `external-scripts.json`, should
be the **FIRST** in the list:

  ```json
  [
    "hubot-enterprise"
  ]
  ```

## configuration
 - Slack Web API Token as `SLACK_APP_TOKEN` environment variable
 - Hubot slack token as `HUBOT_SLACK_TOKEN` environment variable

### Slack Web API token generation:
#### for testing:

**BOT TOKEN (for chat)**
- in slack window, click on your slack team.
- click on `Apps & Integrations`.
- Search for `hubot`.
- Create hubot integration.
- set the token as `HUBOT_SLACK_TOKEN` environment variable.

**API TOKEN (for admin functionality)**
- Go to https://api.slack.com/docs/oauth-test-tokens.
- Generate token from the team, where the bot should run.
- set it as `SLACK_APP_TOKEN` environment variable.

#### for production:

- Follow [set up slack](https://github.com/eedevops/hubot-enterprise/wiki/slack#app-configuration).
- Add the new tokens as environment variables `SLACK_APP_TOKEN` and `HUBOT_SLACK_TOKEN`.

## Commands support

Supported commands:

1. archive old: archiving all channels older than specified time
  * `admin archive older 3<d/h/m/s>`
    - Default patterns: incident, advantage channel names
  * `admin archive older 3<d/h/m/s> <named|tag> pattern1 or pattern2`:
    - Will archive channels with provided pattern names in channel name or tag
    - Default delimiter is `" or "`, can be changed using env `HUBOT_ADMIN_OR`
    - Default channel min length is `3`, can be changed using env `HUBOT_ADMIN_CHANNEL_MIN`
2. Archive specific: archiving specific channel
  * `admin archive channel #channelName`
  * `admin archive channel this` - to archive current channel
  (_cannot archive private chat or #general channel_)
3. enterprise: show enterprise help
  * `@bot-name: enterprise`

## Using Hubot Enterprise with integration
**For more information, please reffer [hubot-enterprise wiki](https://github.com/eedevops/hubot-enterprise/wiki)**

Example scripts:

- [example.coffee](example/example.coffee)
- [admin.coffee](src/admin.coffee)

Write your own:
- Start code file as usual hubot script, add this snippet in the head:

```coffee
module.exports = (robot) ->
 if not robot.e
   robot.logger.error 'hubot-enterprise not present, cannot run'
   return
 robot.logger.info 'hubot-test initialized'
```
- To register a listener call the following code:

```coffee
robot.e.create {action: 'create',
help: 'create ticket', type: 'respond|hear'}, (msg)->
  #your code here

_this = @
@myCallback = (msg) ->
  #your code here

robot.e.create {action: 'create',
help: 'create ticket', type: 'respond|hear'}, _this.myCallback
```
- call will look like that `<product> <action>(.*)`
  - `product` is the suffix of your integration name (`hubot-<product>`)
- if passed `extra: 'regex string'` then the last part will be replaced with this
  - `<product> <action><extra_regex>`

## Testing integration with enterprise support
- install `hubot-enterprise` as dev dependency:
  - `npm install --save-dev eedevops/hubot-enterprise`
- test using hubot-test-helper, currently use this fork: https://github.com/eedevops/hubot-test-helper
  - `npm install --save-dev eedevops/hubot-test-helper`
- follow the documentation of hubot-test-helper with one change:

  ```coffee
  # Helper class should be initialized with this:
  helper = new Helper(['../node_modules/hubot-enterprise/src', <your_module>])
  ```

## DISCLAIMER

Currently hubot-enterprise support slack platform, other platforms might be added later on.
