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


# For emulating of a pair of connected sockets. Bytes written 
# with #write to one side are returned by a subsequent #read on 
# the other side.
#
# Use Pair.stream_pair to get a pair with stream semantics.
# Use Pair.packet_pair to get a pair with packet semantics.
module Orbweaver
  class Pcap
    class IOPair
      attr_reader :read_queue
      attr_accessor :other

      def initialize
          raise NotImplementedError
      end

      def self.stream_pair
          io1 = Stream.new
          io2 = Stream.new
          io1.other = io2
          io2.other = io1
          return io1, io2
      end

      def self.packet_pair
          io1 = Packet.new
          io2 = Packet.new
          io1.other = io2
          io2.other = io1
          return io1, io2
      end

      def write bytes
          @other.read_queue << bytes
          bytes.size
      end

      class Stream < IOPair
          def initialize 
              @read_queue = ""
          end

          def read n=nil
              n ||= @read_queue.size
              @read_queue.slice!(0,n)
          end
      end

      class Packet < IOPair
          def initialize 
              @read_queue = []
          end

          def read 
              @read_queue.shift
          end
      end

    end
  end
end
