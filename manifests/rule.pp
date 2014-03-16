
# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#
# [*source*]
#   The packets source address (in iptables --source
#   supported syntax). Can be an array of sources.
#
# [*destination*]
#    The packets destination (in iptables --destination
#    supported syntax). Can be an array of destinations.
#
# [*source_collection*]
#   Target source name for matching source addresses
#
# [*destination_collection*]
#   Target collection name for matching destination addresses
#
# [*protocol*]
#   The transport protocol (tcp,udp,icmp, anything from /etc/protocols )
#
# [*port*]
#   The DESTINATION port
#
# [*action*]
#   Either 'drop', 'deny' or 'accept'
#
# [*direction*]
#   Either 'input', 'output', 'forward'
#
# [*order*]
#   The CONCAT order where to place your rule.
#
# [*in_interface*]
#   The inbound interface for the rule
#
# [*out_interface*]
#   The outbound interface for the rule
#
# [*log*]
#    Bool. To log the traffic matched by this rule. Default false
#
# [*log_prefix*]
#   Prefix for the lines logged
#
# [*log_limit*]
#   Limit the logging based on iptables --limit directive
#
# [*log_level*]
#   The Iptables log level directive
#
# [*enable*]
#   To enable, or not to enable. That's the question.
#
# [*enable_v4*]
#   Enable IPv4. Defaults to true
#
# [*enable_v6*]
#   Enable IPv6. Defaults to true.
#
# [*debug*]
#   Enable debugging.
#
# [*iptables_chain*]
#   The iptables chain to work on (default INPUT).
#   Write it UPPERCASE coherently with iptables syntax
#
# [*iptables_implicit_matches*]
#   An hashmap with implicit match criteria with the possibility to negate
#   specific matches:
#   { 'dport' => 80, 'tcp-flags' => 'ACK', 'invert' => [ 'tcp-flags'] }
#   Results in: --dport 80 --tcp-flags ! ACK
#
#   See here for a full list of possible implicit criteria:
#     http://www.iptables.info/en/iptables-matches.html#IMPLICITMATCHES
#
# [*iptables_explicit_matches*]
#   An hashmap with explicit match criteria with the possibility to negate
#   specific matches:
#   { 'icmp' => { 'icmp-type' => 8 }, 'hashlimit' => { 'hashlimit' => '1000/sec } }
#   Results in: -m icmp --icmp-type 8 -m hashlimit --hashlimit 1000/sec
#
# [*iptables_target_options*]
#   A hashmap with key=>values of options to be appended after the target.
#
# [*pf_max_src_nodes*]
#   Maximum different source IPs
#
# [*pf_max_src_states*]
#   Maximum amount of states per IP
#
# [*pf_max_src_conn*]
#   Maximum source connections
#
# [*pf_max_src_conn_rate*]
#   Maximum source connections rate (connections per seconds)
#
# [*pf_overload_table*]
#   Table source addresses will be placed in when hitting maximums

define firewall::rule (
  $source                 = '',
  $destination            = '',
  $source_collection      = '',
  $destination_collection = '',
  $protocol               = '',
  $port                   = '',
  $action                 = '',
  $direction              = '',
  $order                  = '',
  $in_interface           = '',
  $out_interface          = '',
  $log                    = $firewall::setup::log,
  $log_prefix             = $firewall::setup::log_prefix,
  $log_limit_burst        = $firewall::setup::log_limit_burst,
  $log_limit              = $firewall::setup::log_limit,
  $log_level              = $firewall::setup::log_level,
  $enable                 = true,
  $enable_v4              = $firewall::setup::enable_v4,
  $enable_v6              = $firewall::setup::enable_v6,
  $debug                  = false,
  $resolve_locations      = true,

  # Iptables specifics
  $iptables_table            = 'filter',
  $iptables_chain            = '',
  $iptables_target           = '',
  $iptables_implicit_matches = {},
  $iptables_explicit_matches = {},
  $iptables_target_options   = {},
  $iptables_rule             = '',

  # PF specifics
  $pf_max_src_nodes     = '',
  $pf_max_src_states    = '',
  $pf_max_src_conn      = '',
  $pf_max_src_conn_rate = '',
  $pf_overload_table    = '',

  $source_v6 = '', # remove me
  $destination_v6 = '', # remove me
  $resolve_failsafe = '', #remove me
) {

#  if $::fqdn == 'icingarelay1.transip.us' and $name == 'apache_tcp_80' {
#    notify { "${name}: enabled v4/6: ${enable_v4} | ${enable_v6} | ${source} | ${destination} | ${apache::manage_firewall}": }
#  }

  include firewall::setup

  $real_direction = $direction ? {
    ''      => 'input',
    default => inline_template('<%= @direction.downcase %>')
  }

  if is_array($source) {
    $source_a = $source
  } else {
    $source_a = $source ? {
      ''                => [],
      default           => [ $source ]
    }
  }

  if is_array($destination) {
    $destination_a = $destination
  } else {
    $destination_a = $destination ? {
      ''                     => [],
      default                => [ $destination ]
    }
  }

  if size($source_a) == 0 and size($destination_a) == 0 {
    $real_source_v4 = []
    $real_source_v6 = []
    $real_destination_v4 = []
    $real_destination_v6 = []
    $real_enable_v4 = true
    $real_enable_v6 = true
  } else {
    $source2_v6      = firewall_resolve_locations($source_a, '6')
    $source_v4       = firewall_resolve_locations($source_a, '4')
    $destination_v4  = firewall_resolve_locations($destination_a, '4')
    $destination2_v6 = firewall_resolve_locations($destination_a, '6')

    if (size($source_a) == 0 and size($destination_a) == 0) {
      $real_enable_v4 = $enable_v4
      $real_enable_v6 = $enable_v6
    } else {
      if ((size($source_a) != 0 and size($source_v4) == 0) or
          (size($destination_a) != 0 and size($destination_v4) == 0)) {
        $real_enable_v4 = false
      } else {
        $real_enable_v4 = $enable_v4
      }
      if ((size($source_a) != 0 and size($source2_v6) == 0) or
          (size($destination_a) != 0 and size($destination2_v6) == 0)) {
        $real_enable_v6 = false
      } else {
        $real_enable_v6 = $enable_v6
      }
    }

    if $real_enable_v4 == false and $real_enable_v6 == false and any2bool($enable) == true {
      fail("A firewall rule was defined but neither IPv6 nor IPv4 was found usable in firewall::rule ${name}")
    }

    $real_source = $source_v4
    $real_destination = $destination_v4
    $real_source_v6 = $source2_v6
    $real_destination_v6 = $destination2_v6

  }


  if ($firewall::setup::rule_class =~ /firewall::rule::iptables/) {

    if $source_collection != '' or $destination_collection != '' {
      fail('No collection support for iptables yet')
    }

    # Embedded here for performance reasons

    # FIXME: Unsure if this should be in firewall or iptables. Maybe both?
    # TODO: Move to iptables - beware of implicit-matches though
    # iptables-restore v1.3.5: Unknown arg `--dport'
    # -A INPUT  --dport 21   -j REJECT
    if ($protocol == '') and ($port) {
      fail('FIREWALL: Protocol must be set if port is set.')
    }

    $real_order = $order ? {
      ''      => $firewall::setup::order,
      default => $order
    }

    $chain = $iptables_chain ? {
      ''      => $firewall::setup::iptables_chains[$real_direction],
      default => $iptables_chain
    }

    $real_iptables_target = $iptables_target ? {
      ''      => $firewall::setup::iptables_targets[$action],
      default => $iptables_target
    }

    iptables::rule { $name:
      table            => $iptables_table,
      chain            => $chain,
      target           => $real_iptables_target,
      in_interface     => $in_interface,
      out_interface    => $out_interface,
      source           => $real_source,
      source_v6        => $real_source_v6,
      destination      => $real_destination,
      destination_v6   => $real_destination_v6,
      protocol         => $protocol,
      port             => $port,
      order            => $real_order,
      log              => $log,
      log_prefix       => $log_prefix,
      log_limit_burst  => $log_limit_burst,
      log_limit        => $log_limit,
      log_level        => $log_level,
      enable           => $enable,
      enable_v4        => $real_enable_v4,
      enable_v6        => $real_enable_v6,
      debug            => $debug,
      implicit_matches => $iptables_implicit_matches,
      explicit_matches => $iptables_explicit_matches,
      target_options   => $iptables_target_options,
      rule             => $iptables_rule
    }
  }
  elsif ($firewall::setup::rule_class =~ /firewall::rule::pf/) {
    # TODO: chain is determined from iptables variable, what to do with it in pf?

    $real_action = $action ? {
        /(deny|reject|drop)/ => 'block',
        default              => 'pass',
    }

    $pf_direction = $real_direction ? {
        'input'    => 'in',
        'incoming' => 'in',
        'output'   => 'out',
        'outgoing' => 'out',
        'forward'  => 'rdr',
        default    => $real_direction
    }

    # TODO: implement forwarding/redirection
    if $pf_direction == 'rdr' {
      fail("direction ${pf_direction} currently not supported")
    }

    pf::rule { $name:
      action            => $real_action,
      direction         => $pf_direction,
      in_interface      => $in_interface,
      out_interface     => $out_interface,
      source            => $real_source,
      source_v6         => $real_source_v6,
      source_table      => $source_collection,
      destination       => $real_destination,
      destination_v6    => $real_destination_v6,
      destination_table => $destination_collection,
      protocol          => $protocol,
      port              => $port,
      order             => $real_order,
      log               => $log,
      enable            => $enable,
      max_src_nodes     => $pf_max_src_nodes,
      max_src_states    => $pf_max_src_states,
      max_src_conn      => $pf_max_src_conn,
      max_src_conn_rate => $pf_max_src_conn_rate,
      overload_table    => $pf_overload_table,
    }
  }
  elsif ($firewall::setup::rule_class =~ /firewall::rule::ipfilter/) {

    if $source_collection != '' or $destination_collection != '' {
      fail('No collection support for ipf yet')
    }


    $real_action = $action ? {
        /(deny|reject|drop)/ => 'block',
        default              => 'pass',
    }

    $ipfilter_direction = $real_direction ? {
        'input'    => 'in',
        'incoming' => 'in',
        'output'   => 'out',
        'outgoing' => 'out',
        default    => $real_direction
    }

    ipfilter::rule { $name:
      action            => $real_action,
      direction         => $ipfilter_direction,
      in_interface      => $in_interface,
      out_interface     => $out_interface,
      source            => $real_source,
      source_v6         => $real_source_v6,
      destination       => $real_destination,
      destination_v6    => $real_destination_v6,
      protocol          => $protocol,
      port              => $port,
      order             => $real_order,
      log               => $log,
      enable            => $enable,
    }
  } else {
    fail("${::firewall::setup::rule_class} unsupported")
  }

}
