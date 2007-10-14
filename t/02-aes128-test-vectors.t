use Test::More tests => 2;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '2b7e151628aed2a6abf7158809cf4f3c');

#is(unpack("B*", $cmac->{L}),   unpack "B*", pack "H*", '7df76b0c1ab899b33e42f047b91b546f');
is(unpack("H*", $cmac->{Lu} ),  'fbeed618357133667c85e08f7236a8de');
is(unpack("H*", $cmac->{Lu2} ), 'f7ddac306ae266ccf90bc11ee46d513b');
