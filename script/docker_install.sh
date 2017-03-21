#!/bin/bash

# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# exit on errors
set -e

# This is a required env variable.
if [ -z "$ADAPTER" ]
then
  echo "ERROR: ADAPTER environment variable must be set"
  exit -1
fi

# set npm proxy- if exists in env
if [ -n "$http_proxy" ]
then
  npm config set http-proxy ${http_proxy}
fi

if [ -n "$https_proxy" ]
then
  npm config set https-proxy ${https_proxy}
fi

# Fix for git communication on proxy-bound environments.
if [ -n "$http_proxy" ] || [ -n "$https_proxy" ] 
then
  git config --global url.https://github.com/.insteadOf git://github.com/
fi

# install adapter if not slack
if [ "${ADAPTER}" != "slack" ]
then
  echo "installing adapter ${ADAPTER}"
  npm install --save hubot-${ADAPTER}
fi

# npm install and add to external-scripts.json from /integration and NPM_INTEGRATIONS
node /he/script/install_integrations.js "/integration" "${NPM_INTEGRATIONS}" .

./bin/hubot --adapter ${ADAPTER}
