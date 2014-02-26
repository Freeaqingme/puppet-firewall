# $custom_rule_class
#   A custom rule class to use.
#
# $linuxFw26
#   The firewall to use for Linux 2.6+ systems. Nftables may be added later
#
class firewall::params (
  $custom_rule_class = '',
  $linuxFw26 = 'iptables'
) {

  if $custom_rule_class != '' {
    $rule_class = $custom_rule_class
  } elsif $kernel =~ /Linux/ {
    $rule_class = 'firewall::rule::iptables'
  } elsif $operatingsystem =~ /FreeBSD/ {
    $rule_class = 'firewall::rule::pf'
  } else {
    $rule_class = ''
  }

  if $rule_class =~ /firewall::rule::iptables/ {

    include iptables

    $order = $iptables::default_order

    $iptables_chains = {
      'output'  => 'OUTPUT',
      'forward' => 'FORWARD',
      'input'   => 'INPUT',
      ''        => 'INPUT'
    }

    $iptables_targets = {
      'deny'    => 'DROP',
      'drop'    => 'DROP',
      'reject'  => 'REJECT',
      'accept'  => 'ACCEPT',
      ''        => $iptables::default_target
    }

    $log             = $iptables::log == 'all'
    $log_prefix      = $iptables::log_prefix
    $log_limit_burst = $iptables::log_limit_burst
    $log_limit       = $iptables::log_limit
    $log_level       = $iptables::log_level

    $enable_v4       = $iptables::enable_v4
    $enable_v6       = $iptables::enable_v6
    $target          = $iptables::default_target
    $service_name    = 'iptables'

  } elsif $rule_class =~ /firewall::rule::pf/ {

    $enable_v4    = true
    $enable_v6    = true
    $service_name = 'pf'

  }
}
