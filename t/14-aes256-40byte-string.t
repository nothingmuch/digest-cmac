use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
$cmac->add(pack 'H*',
    '6bc1bee22e409f96e93d7e117393172a'.
    'ae2d8a571e03ac9c9eb76fac45af8e51'.
    '30c81c46a35ce411'
);
ok($cmac->digest eq pack 'H*', 'aaf3d8f1de5640c232f5b169b9c911e6');

