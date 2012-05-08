package Catalyst::Authentication::Credential::OAuth2;
use Moose;
use MooseX::Types::Moose qw/ Bool HashRef /;
use Catalyst::Exception ();
use namespace::autoclean;
use Net::OAuth2::Client;
use JSON;

=head1 NAME

Catalyst::Authentication::Credential::OAuth2 - OAuth2 credential for Catalyst::Plugin::Authentication framework.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

has debug => ( is => 'ro', isa => Bool );
has providers => ( is => 'ro', isa => HashRef, required => 1 );

=head1 SYNOPSIS

This module is based almost entirely on L<Catalyst::Authentication::Credential::OAuth> - although some of the terminology has changed with OAuth2, I've kept the original parameter names in order to simplify the migration of existing OAuth setups. The only significant difference between the configuration is the addition of the C<callback_url> parameter.

In MyApp.pm

    use Catalyst qw/
        Authentication
        Session
        Session::Store::FastMmap
        Session::State::Cookie
    /;


In myapp.conf

  <Plugin::Authentication>
    default_realm  oauth2
    <realms>
      <oauth2>
        <credential>
          class  OAuth2
          <providers>
            <example.com>
              consumer_key             my_app_key
              consumer_secret          my_app_secret
              callback_url             http://path/to/catalyst/action
              request_token_endpoint   http://example.com/oauth/request_token
              access_token_endpoint    http://example.com/oauth/access_token
              user_auth_endpoint       http://example.com/oauth/authorize
            </example.com>
          </providers>
        </credential>
      </oauth>
    </realms>
 </Plugin::Authentication>

In controller code,

 sub oauth : Local {
   my ($self, $c) = @_;
   
   if( $c->authenticate( { provider => 'example.com' } ) ) {
      #do something with $c->user
   }
 }


=head1 USER METHODS

=cut

=head2 authenticate 


=cut

sub authenticate {
	my ($self, $c, $realm, $auth_info) = @_;

    Catalyst::Exception->throw( "Provider is not defined." )
        unless defined $auth_info->{provider} || defined $self->providers->{ $auth_info->{provider} };

    my $provider = $self->providers->{ $auth_info->{provider} };

    for ( qw/ consumer_key consumer_secret request_token_endpoint access_token_endpoint user_auth_endpoint / ) {
        Catalyst::Exception->throw( $_ . " is not defined for provider ". $auth_info->{provider} )
            unless $provider->{$_};
    }

	$c->log->debug( "authenticate() called from " . $c->request->uri ) if $self->debug;

	# If they're not already logged in, or they're returning with the auth code
	if ( !$c->user && !$c->request->param('code') ) {

		# We need to redirect them to the OAuth2 token request endpoint
		my $url = '%s?client_id=%s&redirect_uri=%s';

		# Some sites (e.g. 37signals and Google) require additional parameters when requesting a token
		my @additional_params;
		map {
			# TODO: URI encode parameters and values
			$url .= sprintf('&%s=%%s', $_); # Deliberate use of sprintf() to reduce line-noise code
			push @additional_params, $provider->{additional_request_params}{$_};
		} keys %{$provider->{additional_request_params}};

		# Redirect the visitor to the provider's token request URL
		return $c->response->redirect(
			sprintf(
				$url,
				$provider->{request_token_endpoint},
				$provider->{consumer_key},
				$provider->{callback_url},
				@additional_params,
		   )
		);
	}

	my $client = Net::OAuth2::Client->new(
		$provider->{consumer_key},
		$provider->{consumer_secret},
		access_token_url => $provider->{access_token_endpoint},
	)->web_server(
		redirect_uri => $provider->{callback_url}
	);

	my $access_token = $client->get_access_token( $c->request->param('code') );
	my $response = $access_token->get($provider->{user_auth_endpoint});

	my $user = decode_json $response->content;

	my $user_obj = $realm->find_user( $user, $c );

	return $user_obj if ref $user_obj;

	$c->log->debug( 'Verified OAuth identity failed' ) if $self->debug;

	return;

}

=head1 AUTHOR

Richard Wallman, C<< <wallmari at bossolutions.co.uk> >>

This module is based on L<Catalyst::Authentication::Credential::OAuth>, changed to use L<Net::OAuth2> to do the heavy lifting.

=head1 BUGS

Please report any bugs or feature requests to C<bug-catalyst-authentication-credential-oauth2 at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Catalyst-Authentication-Credential-OAuth2>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Catalyst::Authentication::Credential::OAuth2


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Catalyst-Authentication-Credential-OAuth2>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Catalyst-Authentication-Credential-OAuth2>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Catalyst-Authentication-Credential-OAuth2>

=item * Search CPAN

L<http://search.cpan.org/dist/Catalyst-Authentication-Credential-OAuth2/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Richard Wallman.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Catalyst::Authentication::Credential::OAuth2
