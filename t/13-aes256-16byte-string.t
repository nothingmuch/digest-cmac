use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
$cmac->add(pack 'H*', '6bc1bee22e409f96e93d7e117393172a');
ok($cmac->digest eq pack 'H*', '28a7023f452e8f82bd4bf28d8c37c35c');

