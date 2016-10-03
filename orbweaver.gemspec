# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'orbweaver/version'

Gem::Specification.new do |spec|
  spec.name          = "orbweaver"
  spec.version       = Orbweaver.version
  spec.authors       = ["Dean Brundage"]
  spec.email         = ["dean@deanandadie.net"]

  spec.summary       = %q{Orbweaver distributed object locator}
  spec.description   = %q{Track networked objects}
  spec.homepage      = "https://github.com/orbweaver-industries/orbweaver"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.9"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "guard-rspec"

  spec.add_runtime_dependency 'ffi-pcap'
  spec.add_runtime_dependency 'packetfu'

end
