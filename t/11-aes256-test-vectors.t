use Test::More tests => 2;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
ok($cmac->{Lu}  eq pack 'H*', 'cad1ed03299eedac2e9a99808621502f');
ok($cmac->{Lu2} eq pack 'H*', '95a3da06533ddb585d3533010c42a0d9');

