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

module Orbweaver
  class Pcap

    class IP < Packet
      IPPROTO_TCP      = 6
      IPPROTO_UDP      = 17
      IPPROTO_HOPOPTS  = 0
      IPPROTO_ROUTING  = 43
      IPPROTO_FRAGMENT = 44
      IPPROTO_AH       = 51
      IPPROTO_NONE     = 59
      IPPROTO_DSTOPTS  = 60
      IPPROTO_SCTP     = 132

      attr_accessor :src, :dst

      def initialize src=nil, dst=nil
          super()
          @src = src
          @dst = dst
      end

      def v4?
          return false
      end

      def v6?
          return false
      end

      def proto
          raise NotImplementedError
      end

      def pseudo_header payload_length
          raise NotImplementedError
      end

      def == other
          return super &&
              self.src    == other.src &&
              self.dst    == other.dst
      end

      def self.checksum bytes
          if bytes.size & 1 == 1
              bytes = bytes + "\0"
          end 
          sum = 0
          bytes.unpack("n*").each {|n| sum += n }
          sum = (sum & 0xffff) + (sum >> 16 & 0xffff)
          ~sum & 0xffff
      end
    end

  end
end
