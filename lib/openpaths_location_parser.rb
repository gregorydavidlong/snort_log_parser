require 'json'

class OpenpathsLocationParser
  def parse filename 
    json = File.read filename
    locations = []
    for location in JSON.parse json
      locations << LocationPoint.json_create(location.collect{ |x| x[1]})
    end
    locations
  end
end

class LocationPoint
  attr_accessor :longitude,
                :latitude, 
                :version, 
                :time, 
                :device, 
                :altitude, 
                :os

  def initialize longitude, latitude, version, time, device, altitude, os
    self.longitude = longitude
    self.latitude = latitude
    self.version = version
    self.time = Time.at time 
    self.device = device
    self.altitude = altitude
    self.os = os
  end

  def self.json_create o
    new *o
  end

  def to_s
    latitude.to_s + "," + longitude.to_s + " (" + time.to_s + ")"
  end
end
