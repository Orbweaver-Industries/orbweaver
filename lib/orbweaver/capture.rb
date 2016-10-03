require 'ffi/pcap'

module Orbweaver
  class Capture

    attr_reader :filters, :pcap

    def initialize(device=nil, pcap=nil, filters=[])
      @device = device
      @filters = filters
      @pcap = pcap || FFI::PCap::Live.new( dev: "wlp2s0" )
      @queue = []
    end


    def capture(&block)
      logger 'capturing'
      if block_given?
        @pcap.loop &block
      else
        @pcap.loop do |this,pkt|
          logger pkt.to_s
        end
      end
    end

  private

    def logger(message)
      @logger ||= Orbweaver::Logger.new
      @logger.log(message)
    end

  end
end
