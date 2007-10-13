use Test::More tests => 2;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '2b7e151628aed2a6abf7158809cf4f3c');


$cmac->add(pack 'H*', '6bc1bee22e409f96e93d7e117393172a');
ok($cmac->digest eq pack 'H*', '070a16b46b4d4144f79bdd9dd04a287c');

$cmac->add(pack 'H*', '6bc1bee22e409f96e93d7e117393172a');
ok($cmac->hexdigest eq '070a16b46b4d4144f79bdd9dd04a287c');
