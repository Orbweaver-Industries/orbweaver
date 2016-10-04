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
require 'orbweaver/pcap/io_wrapper'

module Orbweaver
  class Pcap
    class StreamPacketizer
      attr_reader :io_pair, :parser
      def initialize parser
          @parser = parser
          @key_to_idx = Hash.new do |hash,key|
              if hash.size >= 2
                  raise ArgumentError, "Only two endpoints are allowed in a transaction"
              end
              hash[key] = hash.size
          end
          @sent_messages = [[], []].freeze
          @inner_pair = IOPair.stream_pair
          @io_pair = @inner_pair.map{|io| IOWrapper.new io, parser}.freeze
      end

      def msg_count key
          key = key.inspect
          widx       = @key_to_idx[key]
          messages = @sent_messages[widx]
          messages.size
      end

      def extra_bytes w_key
          w_key = w_key.inspect

          ridx       = @key_to_idx[w_key] ^ 1
          reader = @io_pair[ridx]
          incomplete =  reader.unread
          incomplete.empty? ? nil : incomplete.dup
      end

      def push key, bytes
          key = key.inspect
          widx       = @key_to_idx[key]
          writer     = @io_pair[widx]
          raw_writer = @inner_pair[widx]
          raw_writer.write bytes

          messages = @sent_messages[widx]

          ridx = widx ^ 1
          reader = @io_pair[ridx]
          while msg = reader.read
              messages << msg
              writer.record_write bytes
          end

          nil
      end

      def next_msg key
          key = key.inspect
          idx = @key_to_idx[key] 
          if m = @sent_messages[idx].shift
              return m.dup
          else
              nil
          end
      end
    end
  end
end
