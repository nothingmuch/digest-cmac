use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
$cmac->add('');
ok($cmac->digest eq pack 'H*', '028962f61b7bf89efc6b551f4667d983');

