module Orbweaver
  class PacketHandler
    autoload :AppleGUID, 'orbweaver/packet_handler/apple_guid.rb'
    autoload :EthernetAddress, 'orbweaver/packet_handler/ethernet_address.rb'
    autoload :Generic, 'orbweaver/packet_handler/generic.rb'
  end
end
