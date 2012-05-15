require './openpaths_location_parser'

describe OpenpathsLocationParser do
  before(:each) do
    @parser = OpenpathsLocationParser.new
  end

  describe "a single entry" do
    it "should be parsed correctly" do
      single_entry = "test_data/single_entry.json"
      parsed = @parser.parse(single_entry)
      parsed[0].longitude.should == 144.96456909179688
      parsed[0].latitude.should == -37.797317504882812
      parsed[0].version.should == "1.1"
      parsed[0].time.should == Time.local(2012,05,15,11,55,12)
      parsed[0].device.should == "iPhone3,1"
      parsed[0].altitude.should == 53.332931518554688
      parsed[0].os.should == "5.1.1"
    end
  end

  describe "multiple entries" do
    it "should be parsed correctly"
  end
end
