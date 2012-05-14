require 'snort_log_parser'

describe SnortLogParser do
  before(:each) do
    @test_data_1 = %Q{05/11-05:36:02.774215 123.30.174.116:80 -> 115.146.93.245:57964
TCP TTL:107 TOS:0x0 ID:26770 IpLen:20 DgmLen:40 DF
***A*R** Seq: 0x0  Ack: 0x3C74EF5E  Win: 0x0  TcpLen: 20}

    @test_data_2 = %Q{05/11-05:36:03.623624 1.151.79.26 -> 115.146.94.29
GRE TTL:239 TOS:0x0 ID:20193 IpLen:20 DgmLen:808}

    @logParser = SnortLogParser.new
  end

  describe "from test_data_1" do
    before(:each) do
      @entry = @logParser.parse_entry(@test_data_1)
    end

    it "gets source IP" do
      @entry.source_ip.should == "123.30.174.116"
    end

    it "gets destination IP" do
      @entry.destination_ip.should == "115.146.93.245"
    end
  end

  describe "from test_data_2" do
    before(:each) do
      @entry = @logParser.parse_entry(@test_data_2)
    end

    it "gets source IP" do
      @entry.source_ip.should == "1.151.79.26"
    end

    it "gets destination IP" do
      @entry.destination_ip.should == "115.146.94.29"
    end
  end

end

describe Entry do
  before(:each) do
    #create an entry
    @entry = Entry.new
    @source_ip = "1.2.3.4"
    @entry.source_ip = @source_ip
  end

  it "should have correct source_ip" do
    @entry.source_ip.should == @source_ip
  end
end
