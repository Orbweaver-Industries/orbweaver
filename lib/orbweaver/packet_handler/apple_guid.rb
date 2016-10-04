module Orbweaver
  class PacketHandler
    class AppleGUID < Generic

      APPLE_GUID_RE = /(\$\w{8}-\w{4}-\w{4}-\w{4}-\w{13})/

      def handle(packet)
        if packet.payload =~ APPLE_GUID_RE
          puts $1
        else
          STDERR.puts "discard"
        end
      end

    end
  end
end
