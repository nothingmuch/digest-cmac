use Test::More tests => 2;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '2b7e151628aed2a6abf7158809cf4f3c');

#ok($cmac->{L}  eq pack 'H*', '7df76b0c1ab899b33e42f047b91b546f');
ok($cmac->{Lu}  eq pack 'H*', 'fbeed618357133667c85e08f7236a8de');
ok($cmac->{Lu2} eq pack 'H*', 'f7ddac306ae266ccf90bc11ee46d513b');
