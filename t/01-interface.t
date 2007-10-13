use Test::More tests => 8;
use Digest::CMAC;

my $class = 'Digest::CMAC';

ok($class->can('new'));
ok($class->can('add'));
ok($class->can('digest'));
ok($class->can('reset'));
ok($class->can('hexdigest'));
ok($class->can('b64digest'));
ok($class->can('addfile'));
ok($class->can('add_bits'))
