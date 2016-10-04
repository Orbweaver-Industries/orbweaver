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
      class Chunk
        class Init < Chunk

          attr_accessor :init_tag, :a_rwnd, :o_streams, :i_streams, :init_tsn
    
          def initialize
            super
            @type        = CHUNK_INIT
            @init_tag    = 0
            @a_rwnd      = 0
            @o_streams   = 0
            @i_streams   = 0
            @init_tsn    = 0
            @payload     = []
          end
    
          def self.from_bytes flags, size, bytes
            # Basic validation
            Pcap.assert(bytes.length >= 16, "Truncated init chunk header: 16 > #{bytes.length}")
        
            # Read init chunk header
            init_tag, a_rwnd, o_streams, i_streams, init_tsn = bytes.unpack('NNnnN')
        
            # Create init chunk
            init           = Init.new
            init.flags     = flags
            init.size      = size
            init.init_tag  = init_tag
            init.a_rwnd    = a_rwnd
            init.o_streams = o_streams
            init.i_streams = i_streams
            init.init_tsn  = init_tsn
        
            # Initialize the counter
            length = 16
        
            # Collect the chunks
            while length < bytes.length
              # Parse new parameter from the bytes
              parameter = Parameter.from_bytes(bytes[length..-1])
            
              # Get parameter size with padding
              length += parameter.padded_size
            
              # Add chunk to the list
              init << parameter
            end
        
            return init
          end
    
          def write io, ip
            chunk_header = [@type, @flags, @size].pack('CCn')
            init_header  = [@init_tag,
                            @a_rwnd,
                            @o_streams,
                            @i_streams,
                            @init_tsn].pack('NNnnN')
        
            # Write Chunk header followed by the Init chunk header
            io.write(chunk_header)
            io.write(init_header)
        
            # Write each parameter
            @payload.each do |parameter|
              parameter.write(io, ip)
            end
          end
    
          def << parameter
            @payload << parameter
          end
    
          def to_s
              return "init(%d, %d, %d, %d, %d, %d, %s)" % [@size,
                                                           @init_tag,
                                                           @a_rwnd,
                                                           @o_streams,
                                                           @i_streams,
                                                           @init_tsn,
                                                           @payload.join(", ")]
          end

        end
      end
    end
  end
end
