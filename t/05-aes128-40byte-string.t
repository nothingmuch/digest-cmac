use Test::More tests => 3;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '2b7e151628aed2a6abf7158809cf4f3c');


$cmac->add(pack 'H*',
    '6bc1bee22e409f96e93d7e117393172a'.
    'ae2d8a571e03ac9c9eb76fac45af8e51'.
    '30c81c46a35ce411'
);
ok($cmac->digest eq pack 'H*', 'dfa66747de9ae63030ca32611497c827');
#$cmac->reset;


$cmac->add(pack 'H*', '6bc1bee22e409f96e93d7e117393172a');
$cmac->add(pack 'H*', 'ae2d8a571e03ac9c9eb76fac45af8e51');
$cmac->add(pack 'H*', '30c81c46a35ce411');
ok($cmac->digest eq pack 'H*', 'dfa66747de9ae63030ca32611497c827');
#$cmac->reset;

$cmac->add(
    pack('H*', '6bc1bee22e409f96e93d7e117393172a'),
    pack('H*', 'ae2d8a571e03ac9c9eb76fac45af8e51'),
    pack('H*', '30c81c46a35ce411')
);
ok($cmac->digest eq pack 'H*', 'dfa66747de9ae63030ca32611497c827');

