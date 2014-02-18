
module Puppet::Parser::Functions
  newfunction(:firewall_resolve_srv_targets, :type => :rvalue, :doc => <<-EOS
Resolve targets in SRV records
    EOS
  ) do |args|
    records = args[0]
    raise(ArgumentError, 'Must specify a (set of) record(s)') unless records

    require 'resolv'

    # enforce array or just return empty string
    if records == ''
      return ''
    elsif records.is_a?(String)
      records = [ records ]
    end

    out = []
    typeConst = Resolv::DNS::Resource::IN.const_get('SRV')

    records.each { |record|
      # lookup SRV record
      Resolv::DNS.open do |dns|
        dns.getresources(record, typeConst).collect {|r|
          out.push(r.target)
        }
      end
    }

    return out.length > 0 ? out : ''
  end
end
