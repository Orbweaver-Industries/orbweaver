# Copyright (c) 2011 Mu Dynamics
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'socket'
require 'stringio'

module Orbweaver
  class Pcap
    class ParseError < StandardError ; end


    autoload :Header, 'orbweaver/pcap/header'
    autoload :Pkthdr, 'orbweaver/pcap/pkthdr'
    autoload :Packet 'orbweaver/pcap/packet'
    autoload :Ethernet, 'orbweaver/pcap/ethernet'
    autoload :IP, 'orbweaver/pcap/ip'
    autoload :IPv4, 'orbweaver/pcap/ipv4'
    autoload :IPv6, 'orbweaver/pcap/ipv6'
    autoload :TCP, 'orbweaver/pcap/tcp'
    autoload :UDP, 'orbweaver/pcap/udp'
    autoload :SCTP 'orbweaver/pcap/sctp'

    LITTLE_ENDIAN = 0xd4c3b2a1
    BIG_ENDIAN    = 0xa1b2c3d4

    DLT_NULL      = 0
    DLT_EN10MB    = 1
    DLT_RAW       = 12 # DLT_LOOP in OpenBSD
    DLT_LINUX_SLL = 113

    attr_accessor :header, :pkthdrs
    
    def initialize
        @header = Header.new
        @pkthdrs = []
    end

    # Read PCAP file from IO and return Mu::Pcap.  If decode is true, also
    # decode the Pkthdr packet contents to Mu::Pcap objects.
    def self.read io, decode=true
        pcap = new
        pcap.header = each_pkthdr(io, decode) do |pkthdr|
            pcap.pkthdrs << pkthdr
        end
        return pcap
    end

    # Create PCAP from list of packets.
    def self.from_packets packets
        pcap = new
        packets.each do |packet|
            pkthdr = Pkthdr.new
            pkthdr.pkt = packet
            pcap.pkthdrs << pkthdr
        end
        return pcap
    end

    # Write PCAP file to IO.  Uses big-endian and linktype EN10MB.
    def write io
        @header.write io
        @pkthdrs.each do |pkthdr|
            pkthdr.write io
        end
    end

    # Read PCAP packet headers from IO and return Mu::Pcap::Header.  If decode
    # is true, also decode the Pkthdr packet contents to Mu::Pcap objects.  Use
    # this for large files when each packet header can processed independently
    # - it will perform better.
    def self.each_pkthdr io, decode=true
        header = Header.read io
        while not io.eof?
            pkthdr = Pkthdr.read io, header.magic
            if decode
                pkthdr.decode! header.magic, header.linktype
            end
            yield pkthdr
        end
        return header
    end

    # Read packets from PCAP
    def self.read_packets io, decode=true
        packets = []
        each_pkthdr(io) { |pkthdr| packets << pkthdr.pkt }
        return packets
    end

    # Assertion used during Pcap parsing
    def self.assert cond, msg
        if not cond
            raise ParseError, msg
        end
    end

    # Warnings from Pcap parsing are printed using this method.
    def self.warning msg
        $stderr.puts "WARNING: #{msg}"
    end

    def == other
        return self.class == other.class &&
            self.header   == other.header &&
            self.pkthdrs  == other.pkthdrs
    end
  end

end
