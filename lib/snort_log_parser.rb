class SnortLogParser
  @@re = /(\d{2}\/\d{2})-(\d{2}:\d{2}:\d{2}.\d+)\s(.+)\s->\s(.+)?\n(.+)\sTTL:(\d+)\sTOS:0x[A-F0-9]+\sID:(\d+)\sIpLen:(\d+)\sDgmLen:(\d+)/

  @@entry_separator = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"

  # Parse an entry
  # * *Args* :
  #   - +entry_text+ -> The text for an "entry" in the snort log file
  # * *Returns* :
  #   - The parsed entry text as an +Entry+ object
  #
  def parse_entry(entry_text)
    #puts "Parsing : " + entry_text
    entry = Entry.new
    parsed_array = @@re.match(entry_text)

    #parse the source IP
    parsed_source_ip = parsed_array[3].split(":")
    entry.source_ip = parsed_source_ip[0].to_s
    entry.source_port = parsed_source_ip[1] if parsed_source_ip.length == 2
    fail if entry.source_ip == nil

    #parse the destination IP
    parsed_destination_ip = parsed_array[4].split(":")
    entry.destination_ip = parsed_destination_ip[0].to_s
    entry.destination_port = parsed_destination_ip[1] if parsed_destination_ip.length == 2

    entry.datagram_length = parsed_array[9].to_i
    entry.time = parse_time(parsed_array[1], parsed_array[2])
    entry.packet = entry_text
    entry
  end

  # Parse the time
  # * *Args* :
  #   - +date_string+ -> A string representing the date. Like "mm/dd"
  #   - +time_string+ -> A string representing the time. Like "hh:mm:ss.xxxxxx"
  # * *Returns* :
  #   - Returns the time parsed as a +Time+ object
  #
  def parse_time(date_string, time_string)
    date_match = /(\d+)\/(\d+)/.match(date_string)
    month = date_match[1]
    day = date_match[2]

    time_match = /(\d+):(\d+):(\d+)\.(\d+)/.match(time_string)
    hour = time_match[1]
    minute = time_match[2]
    second = time_match[3]
    Time.utc(2012, month, day, hour, minute, second)
  end

  # Parse the given snort log file into a list of Entry objects
  # * *Args* :
  #   - +filename+ -> The name of the snort file to parse.
  # * *Returns* :
  #   - A list of Entry objects, representing the contents of the snort log file.
  #
  def parse_file(filename)
    entry_text = ""
    entries = []
    File.open(filename).each_line do |line|
      if line.include? @@entry_separator
        entry = parse_entry(entry_text)
        entry_text = ""
        entries << entry
      else
        entry_text << line
      end
    end
    entries
  end

  # Do some analysis. Look for pairs of entries that seem related,
  # that is, match an encrypted packet with its plain text version.
  def analyse(filename, ips_of_interest)
    entries = parse_file(filename)

    # Pairs of entries that we believe are related
    pairs = []
    
    enc_entries = Hash.new
    desired_datagram_lengths = Hash.new

    for entry in entries do

      # Is the entry for an IP we're interested in (i.e. the IP of a mobile device
      for ip in ips_of_interest do
        if (entry.source_ip.include? ip)
          # There should be a corresponding packet that is 41 characters shorter
          desired_datagram_lengths[entry.datagram_length - 41] = ip
          enc_entries[entry.datagram_length - 41] = entry
        end
      end

      matching_ip = desired_datagram_lengths[entry.datagram_length]
      if (matching_ip != nil)
        pairs << [enc_entries[entry.datagram_length], entry]
        desired_datagram_lengths[entry.datagram_length] = nil
        enc_entries[entry.datagram_length] = nil
      end

    end

    # Print the pairs
    #for pair in pairs do
    #  puts "+++++++PAIR+++++++"
    #  puts pair[0].packet
    #  puts pair[1].packet
    #  puts
    #  puts
    #end
    pairs
  end
end

class Entry
  attr_accessor :source_ip, :destination_ip, :datagram_length, :packet, :time, :source_port, :destination_port

  def initialize(hash = nil)
    hash.each do |k,v| 
      instance_variable_set("@#{k}", v)  ## create and initialize an instance variable for this key/value pair 
      instance_eval %Q{ class << self ; attr_reader #{k.intern.inspect} ; end } 
    end if hash != nil 
  end
end
