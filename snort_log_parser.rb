class SnortLogParser
  @@re = /(\d{2}\/\d{2})-(\d{2}:\d{2}:\d{2}.\d+)\s(.+)\s->\s(.+)?\n(.+)\sTTL:(\d+)\sTOS:0x[ABCDEF0123456789]+\sID:(\d+)\sIpLen:(\d+)\sDgmLen:(\d+)/

    @@entry_separator = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"

  def parse_entry(entry_text)
    entry = Entry.new
    parsed_array = @@re.match(entry_text)
    entry.source_ip = parsed_array[3]
    entry.destination_ip = parsed_array[4]
    entry.datagram_length = parsed_array[9]
    entry.packet = entry_text
    entry
  end

  def parse_file(filename)
    entry_text = ""
    entries = []
    File.open(filename).each_line do |line|
      entry_text << line
      if line.include? @@entry_separator
        entry = parse_entry(entry_text)
        entry_text = ""
        entries << entry
      end
    end
    entries
  end
  
end

class Entry
  attr_accessor :source_ip, :destination_ip, :datagram_length, :packet

  def initialize
  end
end
