
define firewall::target_collection::entry (
  $target     = '',
  $collection = ''
) {

  include firewall::setup

  if $target == '' {
    $real_target = $name
  } else {
    $real_target = $target
  }

  $target_res_v4 = firewall_resolve_locations($real_target, '4')
  $target_res_v6 = firewall_resolve_locations($real_target, '6')

  # firewall_resolve_locations can also return a string. We should fix that, but it breaks stuff :(
  if $target_res_v4 == "" {
    $target_res = $target_res_v6
  } elsif $target_res_v6 == "" {
    $target_res = $target_res_v4
  } else {
    $target_res = concat($target_res_v4, $target_res_v6)
  }

  if $target_res == '' {
    fail("No target could be determined for ${name}")
  }

  if ($firewall::setup::rule_class =~ /firewall::rule::iptables/) {
    fail('Not implemented yet')

    iptables::set::entry { $name:
      target => $target_res,
      set    => $collection
    }


  } elsif ($firewall::setup::rule_class =~ /firewall::rule::pf/) {

    pf::table::entry { $name:
      target => $target_res,
      table  => $collection
    }

  } else {
    fail('No collections are supported for this firewall implementation (yet).')
  }

}
