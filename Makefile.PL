use ExtUtils::MakeMaker;

use 5.008;

WriteMakefile(
	NAME              => 'Digest::CMAC',
	VERSION_FROM      => 'lib/Digest/CMAC.pm',
	PREREQ_PM         => {
		'MIME::Base64' => 0,
		'Crypt::Rijndael' => 0,
		'Test::More' => 0,
	},
	ABSTRACT_FROM  => 'lib/Digest/CMAC.pm',
	AUTHOR         => 'Hiroyuki OYAMA <oyama@module.jp>',
);
