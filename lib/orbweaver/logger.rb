module Orbweaver
  class Logger

    DEBUG = 0
    WARN = 1
    INFO = 2

    attr_accessor :log_level

    def initialize
      self.log_level = info
    end


    def log(message, severity=debug)
      if severity <= log_level
        puts message
      end
    end


    def debug; DEBUG; end
    def warn; WARN; end
    def info; INFO; end

  end
end
