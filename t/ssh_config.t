# -*- cperl -*-

use ExtUtils::testlib;
use Test::More ;
use Config::Model ;
use Config::Model::BackendMgr; # required for tests
use Config::Model::Tester::Setup qw/init_test setup_test_dir/;
use English;
use Test::Differences ;
use Test::Warn ;

use warnings;
use strict;

my ($model, $trace) = init_test();

# pseudo root where config files are written by config-model
my $wr_root = setup_test_dir;

my $ssh_subdir = $^O eq 'darwin' ? '/etc'
               :                 '/etc/ssh' ;
my $ssh_path = $wr_root->child($ssh_subdir);

my @orig = <DATA> ;

$ssh_path->mkpath;
my $ssh_file = $ssh_path->child('ssh_config');
$ssh_file->spew(@orig);

print "Test from directory $wr_root\n" if $trace ;

note "Running test like root (no layered config)" ;

my $root_inst = $model->instance (
    root_class_name   => 'SystemSsh',
    instance_name     => 'root_ssh_instance',
    root_dir          => $wr_root,
);

ok($root_inst,"Read $ssh_file and created instance") ;

my $root_cfg = $root_inst -> config_root ;
$root_cfg->init ;

my $dump =  $root_cfg->dump_tree ();
print $dump if $trace ;

like($dump,qr/^#"ssh global comment"/, "check global comment pattern") ;
like($dump,qr/Ciphers=aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,aes256-cbc#"  Protocol 2,1\s+Cipher 3des"/,"check Ciphers comment");
like($dump,qr/SendEnv#"  PermitLocalCommand no"/,"check SendEnv comment");
like($dump,qr/Host:"foo\.\*,\*\.bar"/, "check Host pattern") ;
like($dump,qr/LocalForward:0\s+port=20022/, "check user LocalForward port") ;
like($dump,qr/host=10.3.244.4/, "check user LocalForward host") ;
like($dump,qr/LocalForward:1#"IPv6 example"\s+ipv6=yes/, "check user LocalForward ipv6") ;
like($dump,qr/port=22080/, "check user LocalForward port ipv6") ;
like($dump,qr/host=2001:0db8:85a3:0000:0000:8a2e:0370:7334/, 
     "check user LocalForward host ipv6") ;

$root_inst->write_back() ; 

ok(1,"wrote ssh_config data in $wr_root") ;

my $inst2 = $model->instance (
    root_class_name   => 'SystemSsh',
    instance_name     => 'root_ssh_instance2',
    root_dir          => $wr_root,
);

my $root2 = $inst2 -> config_root ;
my $dump2 = $root2 -> dump_tree ();
print $dump2 if $trace ;

is_deeply([split /\n/,$dump2],[split /\n/,$dump],
	  "check if both root_ssh dumps are identical") ;

done_testing;

__END__
# ssh global comment


Host *
#   ForwardAgent no
#   ForwardX11 no
    Port 1022
#   Protocol 2,1
#   Cipher 3des
    Ciphers aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,aes256-cbc
#   PermitLocalCommand no
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

# foo bar big
# comment
Host foo.*,*.bar
    # for and bar have X11
    ForwardX11 yes
    SendEnv FOO BAR

Host *.gre.hp.com
ForwardX11           yes
User                 tester

Host picosgw
ForwardAgent         yes
HostName             sshgw.truc.bidule
IdentityFile         ~/.ssh/%r
LocalForward         20022         10.3.244.4:22
# IPv6 example
LocalForward         all.com/22080       2001:0db8:85a3:0000:0000:8a2e:0370:7334/80
User                 k0013

Host picos
ForwardX11           yes
HostName             localhost
Port                 20022
User                 ocad
ControlPersist       YES


