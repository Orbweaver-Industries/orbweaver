module Orbweaver
  class Capture
    class Generic

      def initialize(args=nil)
        self.start
        @handlers = []
      end


      def add_handler(h)
        @handlers.push h
      end


      def capturing
        @capturing
      end


      def register_handler(handler)
        @handlers.push handler
      end


      def start
        @capturing = true
      end


      def stop
        @capturing = false
      end

    end
  end
end
