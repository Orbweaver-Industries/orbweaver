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
      class Parameter
        class IpAddress < Parameter

          attr_accessor :value
    
          def initialize
            super
            @value = nil
          end
    
          def self.from_bytes type, size, bytes
            # Basic validation
            if PARAM_IPV4 == type
              Pcap.assert(size == 8, "Invalid IPv4 address: 4 != #{size}")
            else
              Pcap.assert(size == 20, "Invalid IPv6 address: 16 != #{size}")
            end
        
            # Create IP address parameter
            ip_address       = IpAddress.new
            ip_address.type  = type
            ip_address.size  = size
            ip_address.value = IPAddr.new_ntoh(bytes[0, size - 4])
        
            # Set raw payload
            ip_address.payload_raw = bytes[0, size - 4]
        
            # Return the result
            return ip_address
          end
    
          def to_s
            return "address(%s)" % [@value]
          end

        end
      end
    end
  end
end
