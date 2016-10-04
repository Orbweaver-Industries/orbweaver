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
      class Chunk < Packet

        autoload :Data, 'orbweaver/pcap/sctp/chunk/data'
        autoload :Init, 'orbweaver/pcap/sctp/chunk/init'
        autoload :InitAck, 'orbweaver/pcap/sctp/chunk/init_ack'

        attr_accessor :type, :flags, :size
    
        def initialize
          super
          @type  = 0
          @flags = 0
          @size  = 0
        end
    
        def self.from_bytes bytes
          # Basic validation
          Pcap.assert(bytes.length >= 4, "Truncated chunk header: 4 > #{bytes.length}")
        
          # Read chunk header
          type, flags, size = bytes.unpack('CCn')
        
          # Validate chunk size
          Pcap.assert(bytes.length >= size, "Truncated chunk: #{size} set, #{bytes.length} available")
        
          # Create chunk based on type
          case type
              when CHUNK_DATA
                  chunk = Data.from_bytes(flags, size, bytes[4..-1])
              when CHUNK_INIT
                  chunk = Init.from_bytes(flags, size, bytes[4..-1])
              when CHUNK_INIT_ACK
                  chunk = InitAck.from_bytes(flags, size, bytes[4..-1])
              when CHUNK_SACK
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_HEARTBEAT
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_HEARTBEAT_ACK
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_ABORT
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_SHUTDOWN
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_SHUTDOWN_ACK
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_ERROR
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_COOKIE_ECHO
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_COOKIE_ACK
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_ECNE
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_CWR
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_SHUTDOWN_COMPLETE
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_AUTH
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_ASCONF_ACK
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_PADDING
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_FORWARD_TSN
                  chunk = dummy_chunk(type, flags, size, bytes)
              when CHUNK_ASCONF
                  chunk = dummy_chunk(type, flags, size, bytes)
              else
                  chunk = dummy_chunk(type, flags, size, bytes)
          end
        
          # Return the result
          return chunk
        end
    
        def write io, ip
          header = [@type, @flags, @size].pack('CCn')
        
          # Write Chunk header followed by the payload
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
          return "chunk(%d, %d, %d)" % [@type, @flags, @size]
        end
    
        def self.dummy_chunk type, flags, size, bytes
          # Create new dummy chunk
          chunk       = Chunk.new
          chunk.type  = type
          chunk.flags = flags
          chunk.size  = size
        
          # Save the payload
          chunk.payload_raw = chunk.payload = bytes[4..chunk.padded_size]
        
          # Return the result
          return chunk
        end
      end

    end
  end
end
