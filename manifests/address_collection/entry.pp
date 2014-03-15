
define firewall::address_collection::entry (
  $address    = '',
  $collection = ''
) {

  if $address == '' {
    $real_address = $name
  } else {
    $real_address = $address
  }

}
