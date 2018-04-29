
$model_to_test = "Sshd" ;

my $map = {
   'darwin' => '/etc/sshd_config',
   'default' => '/etc/ssh/sshd_config',
} ;

my $target = $map->{$^O} || $map->{default} ;

@tests = (
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
);

1;
