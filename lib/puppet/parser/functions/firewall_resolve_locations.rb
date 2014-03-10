

module Puppet::Parser::Functions
  newfunction(:firewall_resolve_locations, :type => :rvalue, :doc => <<-EOS
Resolve an array containing IP's and hostnames to hostnames.
    EOS
  ) do |vals|
    locations, ip_version = vals
    raise(ArgumentError, 'Must specify a (set of) location(s)') unless locations
    raise(ArgumentError, 'Must specify an IP-version') unless ip_version

    Puppet::Parser::Functions.function(:nslookup)
    require 'ipaddr'

    if locations == ''
      return ''
    elsif locations.is_a?(String)
      locations = [ locations ]
    end

    type = (ip_version == "6" ? 'AAAA' : 'A')
    out = []

    locations.each { |location|
      if !(IPAddr.new(location) rescue nil).nil?
	if (IPAddr.new(location).ipv4?() && ip_version == "4")
        	out << location
	end
	if (IPAddr.new(location).ipv6?() && ip_version == "6")
        	out << location
	end
      else
        out.concat(function_nslookup([ location, type ]))
      end
    }

    return out.length > 0 ? out : ''
  end
end
