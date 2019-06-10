use strict;
use warnings;

my $map = {
   'darwin' => '/etc/sshd_config',
   'default' => '/etc/ssh/sshd_config',
} ;

my $target = $map->{$^O} || $map->{default} ;

my @tests = (
    { 
        name => 'debian-bug-671367' ,
        setup => {
            'system_sshd_config' => $map,
        },
        check => { 
            'AuthorizedKeysFile:0' => '/etc/ssh/userkeys/%u',
            'AuthorizedKeysFile:1' => '/var/lib/misc/userkeys2/%u',
        },
        file_contents_like => {
            $target , qr!/etc/ssh/userkeys/%u /var/lib/misc/userkeys2/%u! ,
        }
    },
    {
        # test that check value is indeed passed when loading Match block
        # that contain a bad value. The bad value is skipped.
        name => 'bad-password-authentication',
        setup => {
            'system_sshd_config' => $map,
        },
        load_check => 'skip',
        check => {
            'Match:0 Settings PermitRootLogin' => 'no',
        }
    }
);

return {
    tests => \@tests,
};

1;
