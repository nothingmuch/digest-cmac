use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');


$cmac->add(pack 'H*',
    '6bc1bee22e409f96e93d7e117393172a'.
    'ae2d8a571e03ac9c9eb76fac45af8e51'.
    '30c81c46a35ce411'
);
ok($cmac->digest eq pack 'H*', '8a1de5be2eb31aad089a82e6ee908b0e');
