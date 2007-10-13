use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '2b7e151628aed2a6abf7158809cf4f3c');


$cmac->add('');
ok($cmac->digest eq pack 'H*', 'bb1d6929e95937287fa37d129b756746');
