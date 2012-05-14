class SnortLogParser
  @@re_1 = /(\d{2}\/\d{2})-(\d{2}:\d{2}:\d{2}.\d+)\s(\d+\.\d+\.\d+\.\d+)(:(\d*))?\s->\s(\d+\.\d+\.\d+\.\d+)(:(\d*))?/

  def parse_entry(entry_text)
    entry = Entry.new
    parsed_array = @@re_1.match(entry_text)
    entry.source_ip = parsed_array[3]
    entry.destination_ip = parsed_array[6]
    entry
  end
end

class Entry
  attr_accessor :source_ip, :destination_ip

  def initialize
  end
end
