require 'pcap'

module Orbweaver
  class Capture
    class IP < Orbweaver::Capture::Generic

      attr_reader :pcap

      def initialize(device: nil, pcap: nil, snaplen: 1516)
        super
        @pcap = pcap || ::Pcap::Capture.open_live(device, snaplen)
      end


      def capture(&block)
        if block_given?
          @pcap.loop(opts) &block
        else
          while capturing do
            @pcap.each_packet do |pkt|
              pkt = Orbweaver::Pcap::Ethernet.from_bytes(pkt.raw_data)
              @handlers.each { |h| h.handle(pkt) }
            end
          end
        end
      end

    end
  end
end
