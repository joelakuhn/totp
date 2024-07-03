<?php

function base32_decode($str) {
  $result = '';
  $A = ord('A');
  $TWO = ord('2');
  $byte = 0;
  $offset = 0;
  foreach (str_split($str) as $c) {
    if ($c >= 'A' && $c <= 'Z') $val = ord($c) - $A;
    else if ($c >= '2' && $c <= '7') $val = ord($c) - $TWO + 26;
    else return null;

    $shift = (8 - $offset) - 5;
    if ($shift < 0) $byte |= $val >> abs($shift);
    else $byte |= $val << $shift;

    $offset += 5;
    if ($offset >= 8) {
      $result .= chr($byte);
      $offset -= 8;
      $byte = $val << (8 - $offset) & 0xff;
    }
  }
  return $result;
}

function otp($secret, $len = 6, $period = 30) {
  $decoded_secret = base32_decode($secret);
  if ($decoded_secret === null) return null;

  $counter = floor(time() / $period);
  $digest = hash_hmac('sha1', pack('J', $counter), $decoded_secret, true);
  $offset = unpack("C", substr($digest, 19, 1))[1] & 0x0F;
  $hotp = unpack("N", substr($digest, $offset, 4))[1] & 0x7FFFFFFF;

  return str_pad(substr($hotp, -$len, $len), $len, '0', STR_PAD_LEFT);
}
