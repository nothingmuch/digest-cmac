use Test::More tests => 2;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
ok($cmac->{Lu}  eq pack 'H*', '448a5b1c93514b273ee6439dd4daa296');
ok($cmac->{Lu2} eq pack 'H*', '8914b63926a2964e7dcc873ba9b5452c');

