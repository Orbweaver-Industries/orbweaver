#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'orbweaver'

c = Orbweaver::Capture::IP.new device: ARGV[0]
#c.add_handler Orbweaver::PacketHandler::EthernetAddress.new
#c.add_handler Orbweaver::PacketHandler::AppleGUID.new

c.capture 
