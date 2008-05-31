package Digest::OMAC2;

use base qw(Digest::OMAC::Base);

use strict;
#use warnings;
use Carp;
use MIME::Base64;

our $VERSION = '0.03';
our $DEBUG => 0;

# we still call it Lu2 even though it's actually no longer squared ;-)

sub _lu2 {
	my ( $self, $blocksize,  $L ) = @_;
	$self->_shift_lu2( $L, $self->_lu2_constant($blocksize) );
}

sub _shift_lu2 {
	my ( $self, $L, $constant ) = @_;

	# used to do Bit::Vector's shift_left but that's broken
	my $unpacked = unpack("B*",$L);
	my $lsb = chop $unpacked;
	my $Lt = pack("B*", "0" . $unpacked);

	if ( $lsb ) {
		return $Lt ^ $constant;
	} else {
		return $Lt;
	}
}

sub _lu2_constant {
	my ( $self, $blocksize ) = @_;

	if ( $blocksize == 16 ) { # 128
		return ("\x80" . ("\x00" x 14) . "\x43");
	} elsif ( $blocksize == 8 ) { # 64
		return ("\x80" . ("\x00" x 6) . "\x0d");
	} else {
		die "Blocksize $blocksize is not supported by OMAC";
	}
}

1;
__END__
