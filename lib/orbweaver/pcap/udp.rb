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

    class UDP < Packet
      attr_accessor :src_port, :dst_port

      def initialize src_port=0, dst_port=0
          super()
          @src_port = src_port
          @dst_port = dst_port
      end

      def flow_id
          return [:udp, @src_port, @dst_port]
      end

      FMT_nnnn = 'nnnn'
      def self.from_bytes bytes
          bytes_length = bytes.length
          bytes_length >= 8 or
              raise ParseError, "Truncated UDP header: expected 8 bytes, got #{bytes_length} bytes"
          sport, dport, length, checksum = bytes.unpack(FMT_nnnn)
          bytes_length >= length or 
              raise ParseError, "Truncated UDP packet: expected #{length} bytes, got #{bytes_length} bytes"
          udp = UDP.new sport, dport
          udp.payload_raw = bytes[8..-1]
          udp.payload = bytes[8..length]
          return udp
      end

      def write io, ip
          length = @payload.length
          length_8 = length + 8
          if length_8 > 65535
              Pcap.warning "UDP payload is too large"
          end
          pseudo_header = ip.pseudo_header length_8
          header = [@src_port, @dst_port, length_8, 0] \
              .pack FMT_nnnn
          checksum = IP.checksum(pseudo_header + header + @payload)
          header = [@src_port, @dst_port, length_8, checksum] \
              .pack FMT_nnnn
          io.write header
          io.write @payload
      end

      def self.udp? packet
          return packet.is_a?(Ethernet) &&
              packet.payload.is_a?(IP) &&
              packet.payload.payload.is_a?(UDP)
      end

      def to_s
          return "udp(%d, %d, %s)" % [@src_port, @dst_port, @payload.inspect]
      end

      def == other
          return super &&
              self.src_port == other.src_port &&
              self.dst_port == other.dst_port
      end
    end

  end
end
