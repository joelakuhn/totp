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

function base32_encode($str) {
  $alphabet = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', '2', '3', '4', '5', '6', '7',
  ];
  $result = '';
  $working = 0;
  $working_n = 0;
  $count = 0;
  foreach (str_split($str) as $c) {
    $working = ($working << 8) + ord($c);
    $working_n += 8;
    while ($working_n >= 5) {
      $result .= $alphabet[$working >> ($working_n - 5)];
      $working_n -= 5;
      $working &= 0xFF >> (8 - $working_n);
      $count += 1;
    }
  }
  if ($working !== 0) {
    $result .= $alphabet[$working << (5 - $working_n)];
    $count += 1;
    if ($count % 8 !== 0) {
      for ($i=0; $i<(8 - ($count % 8)); $i++) {
        $result .= '=';
      }
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
