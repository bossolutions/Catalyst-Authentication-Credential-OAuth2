#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Catalyst::Authentication::Credential::OAuth2' ) || print "Bail out!
";
}

diag( "Testing Catalyst::Authentication::Credential::OAuth2 $Catalyst::Authentication::Credential::OAuth2::VERSION, Perl $], $^X" );
