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

require 'orbweaver/pcap/io_pair'

module Orbweaver
  class Pcap
    class IOWrapper
      attr_reader :ios, :unread, :state

      def initialize ios, reader
          @ios       = ios
          @reader    = reader
          # parse state for reader
          @state     = {}
          # read off of underlying io but not yet processed by @reader
          @unread    = "" 
      end

      # Impose upper limit to protect against memory exhaustion.
      MAX_RECEIVE_SIZE = 1048576 # 1MB

      # Returns next higher level protocol message.
      def read
          until message = @reader.read_message!(@unread, @state)
              bytes = @ios.read
              if bytes and not bytes.empty?
                  @unread << bytes
              else
                  return nil 
              end
              if @unread.size > MAX_RECEIVE_SIZE 
                  raise "Maximum message size (#{MAX_RECEIVE_SIZE}) exceeded"
              end
          end

          return message
      end

      # Parser may need to see requests to understand responses.
      def record_write bytes
          @reader.record_write bytes, @state
      end

      def write bytes, *args
          w = @ios.write bytes, *args
          record_write bytes
          w
      end

      def write_to bytes, *args
          w = @ios.write_to bytes, *args
          record_write bytes
          w
      end

      def open  
          if block_given?
              @ios.open { yield }
          else
              @ios.open
          end
      end

      def open?
          @ios.open?
      end

      def close
          @ios.close
      end
      
    end
  end
end
