
$model_to_test = "Sshd" ;

@tests = (
    { 
        name => 'debian-bug-671367' ,
        setup => {
            'system_sshd_config' => {
                'darwin' => '/etc/sshd_config',
                'default' => '/etc/ssh/sshd_config',
            },
        },
        load_warnings => undef , # some weird warnings pop up in Perl smoke tests with perl 5.15.9
        check => { 
            'AuthorizedKeysFile:0' => '/etc/ssh/userkeys/%u',
            'AuthorizedKeysFile:1' => '/var/lib/misc/userkeys2/%u',
        },
        file_contents_like => {
            '/etc/ssh/sshd_config' => qr!/etc/ssh/userkeys/%u /var/lib/misc/userkeys2/%u! ,
        }
    },
);

1;
