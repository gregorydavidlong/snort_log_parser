require 'snort_log_parser'
require 'openpaths_location_parser'

class Analyser
  def initialize
    @snort_parser = SnortLogParser.new
    @openpaths_parser = OpenpathsLocationParser.new
  end

  # Find a location for the specified pair
  def match_location(snort_pair, locations)
    desired_time = snort_pair[0].time

    previous_location = nil
    #assumes locations are in chronological order
    for location in locations
      #If we have an exact match then just return the location for that time
      return location if location.time == desired_time
     
      if location.time > desired_time
        #find the closest out of the current and previous location
        previous_diff = desired_time - previous_location.time
        current_diff = location.time - desired_time
        if previous_diff <= current_diff
          return previous_location
        else
          return location
        end
      end
      previous_location = location
    end
  end

  def analyse(snortfile, openpathsfile, user_ip)
    snort_pairs = @snort_parser.analyse(snortfile, [user_ip])
    locations = @openpaths_parser.parse(openpathsfile)
    for pair in snort_pairs
      location = match_location(pair, locations)
      puts "Match: at " + location.to_s
      puts pair[1].packet
      puts
      puts
    end
  end
end
