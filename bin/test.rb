#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'orbweaver'

c = Orbweaver::Capture.new device: 'wlp2s0'

c.capture
