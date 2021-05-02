use Config::Model::BackendMgr;
use strict;
use warnings;

# test loading layered config à la ssh_config

my $home_for_test = $^O eq 'darwin' ? '/Users/joe'
                  :                   '/home/joe';

# Ssh backend excepts both system and user files
my %setup = (
    setup => {
        'user_ssh_config' => "$home_for_test/.ssh/config"
    }
);

my @tests = (
    {
        name => 'basic',
        %setup,
        check => [
            'Host:"*" Port' => '1022',

            'Host:"*" Ciphers' => { qw/mode user value/,    'aes192-cbc,aes128-cbc' },
            'Host:"*" Ciphers' => 'aes192-cbc,aes128-cbc',

            #'Host:"foo\.\*,\*\.bar"' => '',
            'Host:picosgw LocalForward:0 port' => 20022,
            'Host:picosgw LocalForward:0 host' => '10.3.244.4',
            'Host:picosgw LocalForward:1 ipv6' => 'yes',
            'Host:picosgw LocalForward:1 port' => 22080,
            'Host:picosgw LocalForward:1 host' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        ],
        verify_annotation => {
            ''                   => 'ssh global comment',
            'Host:"*" SendEnv'   => '  PermitLocalCommand no',
            'Host:"foo.*,*.bar"' => "foo bar big\ncomment",
        }
    },
    {
        name => 'legacy',
        %setup,
        load_check    => 'skip',
        log4perl_load_warnings => [ [
            'User',
            ( warn => qr/deprecated/) x 2,
            warn => qr/Unknown parameter/,
        ] ],
    },
    {
        name => 'bad-forward',
        %setup,
        load_check    => 'skip',
        load => 'Host:"foo.*,*.bar" LocalForward:0 port=20022',
        log4perl_load_warnings => [ [ 'User', warn => qr/value '20022\+' does not match regexp/ ] ],
    },
    {
        name => 'bad-pref-auth',
        %setup,
        load_check    => 'skip',
        log4perl_load_warnings => [
            [ 'User', ( warn => qr/Unexpected authentication method/) , ]
        ],
    },
    {
        name => 'no-user-file',
    },
    {
        name => 'check-host-order',
        data_from => 'basic',
        %setup,
        file_contents_like => {
            # check that picos is still before foo
            "/home/joe/.ssh/config" => qr/Host\s+picos.*?Host\s+foo/s
        }
    },
    {
        name => 'delete-user-file',
        setup => {
            'user_ssh_config' => "$home_for_test/.ssh/config"
        },
        # this removes all custom data from test file. Hence the user
        # file is deleted
        load => 'Host:.clear',
        file_check_sub => sub {
            my $list_ref = shift ;
            # user config removed because load cleared all user data
            pop @$list_ref ;
        }
    },
);

return {
    home_for_test => $home_for_test,
    tests => \@tests,
};
