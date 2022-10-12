require 'packetfu'

module Orbweaver
  class Capture
    class Ethernet < Orbweaver::Capture::Generic

      attr_reader :pcap

      def initialize(device: nil, pcap: nil, snaplen: nil)
        super
        @pcap = pcap || ::PacketFu::Capture.new(iface: device, snaplen: snaplen)
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
