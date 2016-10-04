module Orbweaver
  class PacketHandler
    class EthernetAddress < Generic
      def handle(packet)
        puts packet.src
      end
    end
  end
end
