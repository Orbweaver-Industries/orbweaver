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
    class SCTP

      class Parameter < Packet

        autoload :IpAddress, 'orbweaver/pcap/sctp/parameter/ip_address'

        attr_accessor :type, :size
    
        def initialize
          super
          @type  = 0
          @size  = 0
        end
    
        def self.from_bytes bytes
          # Basic validation
          Pcap.assert(bytes.length >= 4, "Truncated parameter header: 4 > #{bytes.length}")
        
          # Read chunk header
          type, size = bytes.unpack('nn')
        
          # Validate chunk size
          Pcap.assert(bytes.length >= size, "Truncated parameter: #{size} set, #{bytes.length} available")
        
          # Create chunk based on type
          case type
            when PARAM_IPV4
                parameter = IpAddress.from_bytes(type, size, bytes[4..-1])
            when PARAM_IPV6
                parameter = IpAddress.from_bytes(type, size, bytes[4..-1])
            when PARAM_STATE_COOKIE
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_COOKIE_PRESERVATIVE
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_HOST_NAME_ADDR
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_SUPPORTED_ADDR_TYPES
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_ECN
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_RANDOM
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_CHUNK_LIST
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_HMAC_ALGORITHM
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_PADDING
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_SUPPORTED_EXTENSIONS
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_FORWARD_TSN
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_SET_PRIMARY_ADDR
                parameter = dummy_parameter(type, size, bytes)
            when PARAM_ADAPTATION_LAYER_INDICATION
                parameter = dummy_parameter(type, size, bytes)
            else
                parameter = dummy_parameter(type, size, bytes)
          end

          return parameter
        end
    
        def write io, ip
          header = [@type, @size].pack('nn')
        
          # Write Parameter header followed by the payload
          io.write(header)
          io.write(@payload_raw)
        end
    
        def padded_size
          if 0 == @size % 4
            return @size
          else
            return (@size + 4 - (@size % 4))
          end
        end
    
        def to_s
          return "parameter(%d, %d)" % [@type, @size]
        end
    
        def self.dummy_parameter type, size, bytes
          # Create new dummy parameter
          parameter       = Parameter.new
          parameter.type  = type
          parameter.size  = size
        
          # Save the payload
          parameter.payload = bytes[4..parameter.padded_size - 1]
          parameter.payload_raw = parameter.payload

          # Return the result
          return parameter
        end

      end
    end
  end
end
