require 'analyse'

describe Analyser do
  before (:each) do
    @analyser = Analyser.new
  end

  it "should match snort log files with location data" do
    snortfile = "traffic_data/log_20120515/snort.log.1337044274.txt"
    openpathsfile = "location_data/openpaths_gregorydavidlong.json"
    user_ip = "1.139.177.134"
    @analyser.analyse(snortfile, openpathsfile, user_ip)
  end

  describe "matching" do
    describe "a single data entry" do
      before(:each) do
        @location = LocationPoint.new 1, 1, "v1", Time.at(100000), "device", 1, "os"
        args = { 
          :source_ip => "1.2.3.4", 
          :destination_ip => "2.3.4.5", 
          :datagram_length => 42, 
          :packet => "abcdefg", 
          :time => Time.at(100000), 
          :source_port => nil, 
          :destination_port => nil 
        }
        entry1 = Entry.new args
        entry2 = Entry.new args.replace({ 
          :time => Time.at(100200),
          :datagram_length => 1,
          :packet => "12345" 
        })

        @pair = [entry1, entry2]
      end

      it "should work for a single location" do
        @analyser.match_location(@pair, [@location]).should == @location
      end

      describe "for multiple locations" do
        before(:each) do
          @location2 =  LocationPoint.new 2, 2, "v1", Time.at(200000), "device", 2, "os"
          @locations = [ 
            @location,
            @location2,
            LocationPoint.new(3, 3, "v1", Time.at(300000), "device", 2, "os"),
          ]
        end

        it "with an exact match" do
          @analyser.match_location(@pair, @locations).should == @location
        end

        it "with an exact match in the middle" do
          args = { 
            :source_ip => "1.2.3.4", 
            :destination_ip => "2.3.4.5", 
            :datagram_length => 42, 
            :packet => "abcdefg", 
            :time => Time.at(200000), 
            :source_port => nil, 
            :destination_port => nil 
          }
          entry1 = Entry.new args
          entry2 = Entry.new args.replace({ 
            :time => Time.at(200200),
            :datagram_length => 1,
            :packet => "12345" 
          })
          @pair = [entry1, entry2]
          @analyser.match_location(@pair, @locations).should == @location2
        end

        it "without an exact match, close to the subsequent location" do
          args = { 
            :source_ip => "1.2.3.4", 
            :destination_ip => "2.3.4.5", 
            :datagram_length => 42, 
            :packet => "abcdefg", 
            :time => Time.at(190000), 
            :source_port => nil, 
            :destination_port => nil 
          }
          entry1 = Entry.new args
          entry2 = Entry.new args.replace({ 
            :time => Time.at(190200),
            :datagram_length => 1,
            :packet => "12345" 
          })
          @pair = [entry1, entry2]
          @analyser.match_location(@pair, @locations).should == @location2
        end

        it "without an exact match, close to the previous location" do
          args = { 
            :source_ip => "1.2.3.4", 
            :destination_ip => "2.3.4.5", 
            :datagram_length => 42, 
            :packet => "abcdefg", 
            :time => Time.at(110000), 
            :source_port => nil, 
            :destination_port => nil 
          }
          entry1 = Entry.new args
          entry2 = Entry.new args.replace({ 
            :time => Time.at(110200),
            :datagram_length => 1,
            :packet => "12345" 
          })
          @pair = [entry1, entry2]
          @analyser.match_location(@pair, @locations).should == @location
        end

      end
    end

    describe "multple data entries" do
      it "should work for a single location"
      it "should work for multiple locations"
    end
  end
end
