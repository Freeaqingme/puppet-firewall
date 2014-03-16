
define firewall::target_collection {

  include firewall::setup

  if ($firewall::setup::rule_class =~ /firewall::rule::iptables/) {
    fail('Not implemented yet')

    iptables::set { $name: }


  } elsif ($firewall::setup::rule_class =~ /firewall::rule::pf/) {
    pf::table { $name: }

  } else {
    fail('No collections are supported for this firewall implementation (yet).')
  }

}

