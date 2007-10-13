use Test::More tests => 1;
use Digest::CMAC;

my $cmac = Digest::CMAC->new(pack 'H*', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');


$cmac->add('');
ok($cmac->digest eq pack 'H*', 'd17ddf46adaacde531cac483de7a9367');
