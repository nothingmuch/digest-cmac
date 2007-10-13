package Digest::CMAC;

use strict;
#use warnings;
use Carp;
use MIME::Base64;

our $VERSION = '0.02';
our $DEBUG => 0;


sub new {
    my $class = shift;
    my $key = shift;
    my $cipher = shift;
    $cipher ||= 'Crypt::Rijndael';

    my $self = bless {
        cipher => undef,
        key => '',
        ix  => 0,
        iv  => '',
        Lu  => '',
        Lu2 => '',
    }, $class;
    return $self->_init($key, $cipher);
}

sub add {
    my $self = shift;
    my @msg = unpack 'C*', join '', @_;
    my $in_l = length join '', @_;
    my $blocksize = $self->{cipher}->blocksize;
    my @iv = unpack 'C*', $self->{iv};

    my $m_pos = 0;
    if ($in_l < $blocksize - $self->{ix}) {
        while ($in_l--) {
            $iv[$self->{ix}++] ^= $msg[$m_pos++];
        }
        if (scalar @msg > 0) {
            $self->{iv} = to_bin(\@iv);
        }
        return $self;
    }
    if ($self->{ix}) {
        while ($self->{ix} < $blocksize) {
            --$in_l;
            $iv[$self->{ix}++] ^= $msg[0];
        }
        @iv = unpack 'C*', $self->{cipher}->encrypt(to_bin(\@iv));
    }
    while ($in_l > $blocksize) {
        for (my $i = 0; $i < $blocksize/1; $i++) {
            $iv[$i] ^= $msg[$i];
        }
        @iv = unpack 'C*', $self->{cipher}->encrypt(to_bin(\@iv));
        @msg = splice @msg, $blocksize;
        $in_l -= $blocksize;
    }
    for (my $i = 0; $i < $in_l; $i++) {
        $iv[$i] ^= $msg[$i];
    }
    $self->{iv} = to_bin(\@iv);
    $self->{ix} = $in_l;

    return $self;
}

sub digest {
    my $self = shift;
    my $blocksize = $self->{cipher}->blocksize;
    my @iv = unpack 'C*', $self->{iv};
    my @Lu = unpack 'C*', $self->{Lu};
    my @Lu2 = unpack 'C*', $self->{Lu2};

    if ($self->{ix} != $blocksize) {
        $iv[$self->{ix}] ^= 0x80;
        for (my $i = 0; $i < $blocksize/1; $i++) {
            $iv[$i] ^= $Lu2[$i];
        }
    }
    else {
        for (my $i = 0; $i < $blocksize/1; $i++) {
            $iv[$i] ^= $Lu[$i];
        }
    }
    my $result = $self->{cipher}->encrypt(to_bin(\@iv));
    $self->reset;
    $result;
}

sub reset {
    my $self = shift;
    my $blocksize = $self->{cipher}->blocksize;

    $self->{ix} = 0;
    $self->{iv} = pack "x$blocksize", 0;
    return $self;
}


sub _init {
    my $self = shift;
    my $key = shift;
    my $cipher = shift;

    eval "require $cipher; 1;"
        or croak "Couldn't load $cipher: $@";
    $self->{cipher} = $cipher->new($key);
    my $blocksize = $self->{cipher}->blocksize;

    $self->{iv} = pack "x$blocksize", 0;
    my $L = pack "x$blocksize", 0;
    # init L
    $L = $self->{cipher}->encrypt($L);
    $self->{ix} = 0;
    if ($DEBUG) { printf STDERR qq{DEBUG >> L=%s\n}, unpack 'H*', $L; }

    # init Lu
    my @L = unpack 'C*', $L;
    my @Lu = unpack 'C*', pack "x$blocksize", 0;
    my $cond = $L[0] & 0x80;
    $Lu[0] = $L[0] << 1;
    for (my $i = 1; $i < $blocksize; $i++) {
        $Lu[$i-1] |= $L[$i] >> 7;
        $Lu[$i]    = $L[$i] << 1;
        $Lu[$i-1] &= 0xff;
        $Lu[$i]   &= 0xff;
    }
    if ($cond) {
        $Lu[$blocksize-1] ^= 0x87;
    }
    $self->{Lu} = to_bin(\@Lu);
    if ($DEBUG) { printf STDERR qq{DEBUG >> Lu=%s\n}, unpack 'H*', $self->{Lu}; }

    # init Lu2
    my @Lu2 = unpack 'C*', pack "x$blocksize", 0;
    $cond = $Lu[0] & 0x80;
    $Lu2[0] = $Lu[0] << 1;
    $Lu2[0] &= 0xff;
    for (my $i = 1; $i < $blocksize; $i++) {
        $Lu2[$i-1] |= $Lu[$i] >> 7;
        $Lu2[$i]    = $Lu[$i] << 1;
        $Lu2[$i-1] &= 0xff;
        $Lu2[$i]   &= 0xff;
    }
    if ($cond) {
        $Lu2[$blocksize-1] ^= 0x87;
    }
    $self->{Lu2} = to_bin(\@Lu2);
    if ($DEBUG) { printf STDERR qq{DEBUG >> Lu2=%s\n}, unpack 'H*', $self->{Lu2}; }

    return $self;
}


# support methods
sub hexdigest {
    return unpack 'H*', $_[0]->digest;
}

sub b64digest {
    my $result = MIME::Base64::encode($_[0]->digest);
    $result =~ s/=+$//;
    return $result;
}

sub addfile {
    my $self = shift;
    my $handle = shift;
    my $n;
    my $buff = '';

    while (($n = read $handle, $buff, 4*1024)) {
        $self->add($buff);
    }
    unless (defined $n) {
        croak "read failed: $!";
    }
    return $self;
}

sub add_bits {
    my $self = shift;
    my $bits;
    my $nbits;

    if (scalar @_ == 1) {
        my $arg = shift;
        $bits = pack 'B*', $arg;
        $nbits = length $arg;
    }
    else {
        $bits = shift;
        $nbits = shift;
    }
    if (($nbits % 8) != 0) {
        croak 'Number of bits must be multiple of 8 for this algorithm';
    }
    return $self->add(substr $bits, 0, $nbits/8);
}


# internal use function
sub to_bin {
    my $l = shift;
    return pack 'C*', @$l;
}

1;
__END__

=head1 NAME

Digest::CMAC - The One-key CBC MAC message authentication code.

=head1 SYNOPSIS

  use Digest::CMAC;
  my $omac1 = Digest::CMAC->new($key);
  
  $omac1->add($data);
  
  my $binary_tag = $omac1->digest;
  my $hex_tag    = $omac1->hexdigest;
  my $base64_tag = $omac1->b64digest;

=head1 DESCRIPTION

This module implements OMAC1 blockcipher-based message authentication code for perl. For OMAC1/OMAC. Check http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html. Here is an excerpt of that page

=over 4

OMAC is a blockcipher-based message authentication code designed and analyzed by me and Kaoru Kurosawa.

OMAC is a simple variant of the CBC MAC (Cipher Block Chaining Message Authentication Code). OMAC stands for One-Key CBC MAC.

OMAC allows and is secure for messages of any bit length (while the CBC MAC is only secure on messages of one fixed length, and the length must be a multiple of the block length). Also, the efficiency of OMAC is highly optimized. It is almost as efficient as the CBC MAC.

"NIST Special Publication 800-38B Recommendation for Block Cipher Modes of Operation: the CMAC Mode for Authentication" has been finalized on May 18, 2005. This Recommendation specifies CMAC, which is equivalent to OMAC (OMAC1).

=back 4

Like many block-cipher's Crypt:: modules like L<Crypt::Rijndael>, and L<MIME::Base64>.

=head1 METHODS

=over 4

=item new

  my $omac1 = Digest::CMAC->new($key [, $cipher]);

This creates a new Digest::CMAC object, using $key.

$cipher is 'Crypt::Rijndael'(default), 'Crypt::Misty1', Crypt::Blowfish', or whatever blockcipher you like. $key is fixed length string that blockcipher demands. 

=item add

  $omac1->add($message,...);

The $message provided as argument are appended to the message we calculate the MAC. The return value is the $cmac object itself;

=item reset

  $omac1->reset;

This is just an alias for $cmac->new;

=item digest

  my $digest = $omac1->digest;

Return the binary authentication code for the message. The returned string will be blockcipher's block size.

=item hexdigest

  my $digest = $omac1->hexdigest;

Same as $cmac->digest, but will return the digest in hexadecimal form.

=item b64digest

Same as $omac1->digest, but will return the digest as a base64 encoded string.

=back

=head1 SEE ALSO

L<Crypt::Rijndael>,
http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html,
http://www.csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf

=head1 AUTHOR


OMAC designed and analyzed by
Tetsu Iwata and Kaoru Kurosawa

"Crypt::CMAC" was written by
Hiroyuki OYAMA <oyama@module.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Hiroyuki OYAMA

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
