use strict;

use Config::Model::BackendMgr;

# test loading layered config à la ssh_config

$model_to_test = "SystemSsh";
$conf_file_name = "ssh_config";
$conf_dir= '/etc/ssh';

@tests = (
    {    # t0
        name  => 'basic',
        check => {
            'Host:"*" Ciphers' => 'aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc',
            'Host:"*" IdentityFile:1' => '~/.ssh/id_rsa',
            #'Host:"foo\.\*,\*\.bar"' => '',
            # 'LocalForward:0 port' => 20022,
            # 'LocalForward:0 host' => 10.3.244.4,
            # 'LocalForward:1 ipv6' => 1,
            # 'LocalForward:1 port' => 22080,
            # 'LocalForward:1 host' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        },
    }
);

1;
