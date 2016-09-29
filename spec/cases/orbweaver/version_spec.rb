require 'spec_helper'

describe Orbweaver do

  it 'has a version number' do
    expect(Orbweaver.version).to be_a String
  end

  it 'responds to :version' do
    expect(Orbweaver).to respond_to :version
  end

end
