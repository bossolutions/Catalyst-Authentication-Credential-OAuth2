use inc::Module::Install;

name 'Catalyst-Authentication-Credential-OAuth2';
all_from 'lib/Catalyst/Authentication/Credential/OAuth2.pm';

requires 'Moose';
requires 'Net::OAuth2';
requires 'MooseX::Types';
requires 'namespace::autoclean';
requires 'JSON';

test_requires 'Catalyst::Runtime';
test_requires 'Test::More';

resources repository => 'https://github.com/bossolutions/Catalyst-Authentication-Credential-OAuth2';

if ($Module::Install::AUTHOR) {
    system("pod2text lib/Catalyst/Authentication/Credential/OAuth2.pm > README")
        and die;
}

WriteAll();
