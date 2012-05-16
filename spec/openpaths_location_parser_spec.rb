# Copyright (c) 2012, VeRSI Consortium, Gregory Long
#   (Victorian eResearch Strategic Initiative, Australia)
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the VeRSI, the VeRSI Consortium members, nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'openpaths_location_parser'

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
    it "should be parsed correctly" do
      multiple_entries = "test_data/multiple_entries.json"
      parsed = @parser.parse(multiple_entries)
      parsed.length == 3
    end
  end
end
