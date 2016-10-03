#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'orbweaver'

h = Orbweaver::PacketHandler::EthernetAddress.new
c = Orbweaver::Capture::IP.new device: ARGV[0]
c.add_handler h

c.capture 
