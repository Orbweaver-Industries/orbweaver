require 'ffi/pcap'

module Orbweaver
  class Capture
    class IP < Orbweaver::Capture::Generic

      attr_reader :pcap

      def initialize(device: nil, pcap: nil)
        super
        @device = device
        @pcap = pcap || FFI::PCap::Live.new( device: @device )
      end


      def capture(opts={},&block)
        if block_given?
          @pcap.loop(opts) &block
        else
          while capturing do
            @pcap.loop(opts) do |this,pkt|
              @handlers.each { |h| h.handle(pkt) }
            end
          end
        end
      end

    end
  end
end
