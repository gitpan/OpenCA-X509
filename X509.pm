## OpenCA::X509
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
package OpenCA::X509;

$VERSION = '0.8.38';

my %params = (
	 cert => undef,
	 pemCert => undef,
	 derCert => undef,
	 txtCert => undef,
	 backend => undef,
	 parsedCert => undef,
	 certFormat => "PEM",
);

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };
	my $infile, $tmp;

        $self->{cert} 	    = $keys->{DATA};
	$self->{certFormat} = $keys->{FORMAT};
	$infile		    = $keys->{INFILE};

	$self->{backend}    = $keys->{SHELL};

        if( "$self->{certFormat}" eq "" ) {
                $self->{certFormat} = "PEM";
        }

	if( $infile ) {
		$self->{cert} = "";

		open(FD, "<$infile" ) or return;
		while ( $tmp = <FD> ) {
			$self->{cert} .= $tmp;
		}
		close(FD);
	}

	if ( $self->{cert} ne "" ) {
		if ( not $self->initCert( CERTIFICATE=>$self->{cert},
					  FORMAT=>$self->{certFormat})) {
			return;
		}

	}

        return $self;
}

sub initCert {
	my $self = shift;
	my $keys = { @_ };

	$self->{cert} = $keys->{CERTIFICATE};
	$self->{certFormat} =>$keys->{FORMAT};

	return if (not $self->{cert});

	$self->{pemCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>CERTIFICATE,
					INFORM=>$self->{certFormat},
					OUTFORM=>PEM );
	$self->{derCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>CERTIFICATE,
					INFORM=>$self->{certFormat},
					OUTFORM=>DER );
	$self->{txtCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>CERTIFICATE,
					INFORM=>$self->{certFormat},
					OUTFORM=>TXT );

	$self->{parsedCert} = $self->parseCert( CERTIFICATE=> $self->{txtCert} );

	return if ( (not $self->{pemCert}) or (not $self->{derCert})
		 or (not $self->{txtCert})  or (not $self->{parsedCert}) );

	return 1;
}

sub getParsed {
	my $self = shift;

	return if ( not $self->{parsedCert} );
	return $self->{parsedCert};
}

sub parseCert {

	my $self = shift;
	my $keys = { @_ };

	my $textCert = $keys->{CERTIFICATE};
	my @dnList = ();

	my @ouList;
	my @exts;
	
	my $ret;

	return if (not $textCert);

	## Parse Certificate and set right values;
	( $ret->{VERSION} ) = ( $textCert =~ /Version: ([a-e\d]+)/i );
        ( $ret->{SERIAL} )  = ( $textCert =~ /Serial Number:[^x]*.([^\)]+)/i );
        ( $ret->{DN} )      = ( $textCert =~ /Subject: ([^\n]+)/i );

	if ( length( $ret->{SERIAL} ) % 2 ) {
        	$ret->{SERIAL} = "0" . $ret->{SERIAL};
	};

        $ret->{SERIAL} = uc( $ret->{SERIAL} );

	## Split the Subject into separate fields
	@dnList = split( /[\,\/]+/, $ret->{DN} );

	## Analyze each field
	foreach $tmp (@dnList) {
		my $key, $val;

		next if ( not $tmp );

		( $key, $val ) = ( $tmp =~ /([\S]+?)=(.*)/ );
		$key = uc ( $key );

		## The OU variable is a list
		if( $key eq "OU" ) {
			push @ouList, $val;
		} else {
			$ret->{$key} = $val;
		}
	}

        ( $ret->{ISSUER} ) = ( $textCert =~ /Issuer: ([^\n]+)/i );

        ( $ret->{NOT_BEFORE} ) = ( $textCert =~ /Not Before: ([^\n]+)/i );
        ( $ret->{NOT_AFTER} )  = ( $textCert =~ /Not after : ([^\n]+)/i );

        ( $ret->{PK_ALGORITHM} ) =
			 ( $textCert =~ /Public Key Algorithm: ([^\n]+)/i );

        ( $ret->{MODULUS} )  = ( $textCert =~ /Modulus \(([\d]+)/i );
        ( $ret->{EXPONENT} ) = ( $textCert =~ /Exponent: ([\d]+)/i );

        ( $ret->{EXTS} ) = [ @exts ];
        ( $ret->{OU} )   = [ @ouList ];

	return $ret;
}

sub getPEM {
	my $self = shift;
	return if (not $self->{pemCert});

	return $self->{pemCert};
}

sub getDER {
	my $self = shift;

	return if( not $self->{derCert} );
	return $self->{derCert};
}

sub getTXT {
	my $self = shift;

	return if( not $self->{txtCert} );
	return $self->{txtCert};
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::X509 - Perl extension for basic handling x509 Certificates.

=head1 SYNOPSIS

use OpenCA::X509;

=head1 DESCRIPTION

This module contains all functions needed for handling of X509
certificates. It requires some parameters to be passed such as
a reference to a OpenCA::OpenSSL instance. 
 
This module provides an interface to X509 structures, no specific
crypto functions are performed (see the OpenCA::OpenSSL module
for this). When not said different, default operational format is
PEM.

=head1 FUNCTIONS

=head2 sub new () - Create a new instance of the Class.

	This function creates an instance of the module. If you
	provide a certificate it will be parsed and stored in
	local variable(s) for later usage. The function will return
	a blessed reference.

	Accepted parameters are:

		SHELL       - Reference to an initialized
			      OpenCA::OpenSSL instance;
		CERTIFICATE - Certificate to stored in structure(*);
		INFILE      - Certificate file(*);
		FORMAT	    - Format of the provided certificate,
			      one of PEM|DER|NET(*);

	(*) - Optional parameter.

	EXAMPLE:

	      $x509 = new OpenCA::X509( SHELL=>$crypto,
					CERTIFICATE=>$self->{cert});

=head2 sub initCert () - Use a new certificate.

	You can use a new certificate without having to get a
	new module reference. Accepted parameters are:

		CERTIFICATE   - Certificate data to be stored;
		FORMAT        - Provided certificate's format,
				one of PEM|DER|NET(*);

	EXAMPLE:

		if( not $x509->initCert( CERTIFICATE=>$self->{cert} ) ) 
                {
                    print "Error in storing certificate!";
                }

=head2 sub getParsed () - Get an hash structure from certificate

	By calling this function you can retrieve a reference to the
	parsed certificate (PERL hash). This structure will include,
	for example:

		$ret->{SERIAL}		## Serial Number
                $ret->{DN}		## Subject DN
                $ret->{EMAIL}		## Subject e-mail
                $ret->{CN}		## Subject CN
                $ret->{OU}		## Subject OU (list)
                $ret->{O}		## Subject Organization
                $ret->{C}		## Subject Country
                $ret->{ISSUER}		## Issuer DN
                $ret->{NOT_BEFORE}	## Not Before Date
                $ret->{NOT_AFTER}	## Not After Date (Expiration)
                $ret->{PK_ALGORITHM}	## Algorithm used (RSA,DSA,..)
                $ret->{MODULUS}		## Modulus (Size in bits)
                $ret->{EXPONENT}	## Exponent

	EXAMPLE:

		my $self->{parsedCert} = $x509->parseCertificate();

		print $self->{parsedCert}->{SERIAL};
		foreach $ou ( @{ $self->{parsedCert}->{OU} } ) {
			print "OU=$ou, ";
		}

=head2 sub status () - Get certificate status

	Get certificate status using provided OpenCA::CRL initialized
	reference as argument. Returned status can be Valid, Revoked,
	Expired and Unknown. Accepted arguments:

		CRL   - Crl to check certificate status;

	The returned structure is:

		$status->{STATUS};
		$status->{REVOKATION_DATE};
		$status->{EXPIRATION_DATE};

	EXAMPLE:

		my $status = $x509->status( CRL=>$crl );
		print $status->{STATUS};

=head2 sub getPEM () - Get certificate in PEM format.

	Get certificate in PEM format.

	EXAMPLE:

		$pem = $x509->getPEM();

=head2 sub getDER () - Get certificate in DER format.

	Get certificate in DER format.

	EXAMPLE:

		$der = $x509->getDER();

=head2 sub getTXT () - Get certificate in TXT format.

	Get certificate in TXT format.

	EXAMPLE:

		$der = $x509->getTXT();

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::CRL, OpenCA::REQ, OpenCA::X509

=cut
