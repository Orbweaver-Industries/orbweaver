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

    class Reader

      autoload :HttpFamily, 'orbweaver/pcap/reader/http_family'

      attr_accessor :pcap2scenario

      FAMILY_TO_READER = {}

      # Returns a reader instance of specified family. Returns nil when family is :none.
      def self.reader family
          if family == :none
              return nil
          end

          if klass = FAMILY_TO_READER[family]
              return klass.new
          end

          raise ArgumentError, "Unknown protocol family: '#{family}'"
      end

      # Returns family name 
      def family
          raise NotImplementedError
      end

      # Notify parser of bytes written. Parser may update state
      # to serve as a hint for subsequent reads.
      def record_write bytes, state=nil
          begin
              do_record_write bytes, state
          rescue
              nil
          end
      end

      # Returns next complete message from byte stream or nil. 
      def read_message bytes, state=nil
          read_message! bytes.dup, state
      end

      # Mutating form of read_message. Removes a complete message
      # from input stream. Returns the message or nil if there. 
      # is not a complete message.
      def read_message! bytes, state=nil
          begin
              do_read_message! bytes, state
          rescue
              nil
          end
      end

    end
  end
end
