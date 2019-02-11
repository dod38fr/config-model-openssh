use strict;
use warnings;
use lib qw(contrib/lib);
use 5.22.0;

use ParseMan;

use Test::More;
use Test::Differences;
use Path::Tiny;
use experimental qw/postderef signatures/ ;

my $html = path('xt/ssh.html')->slurp;

my $data = parse_html_man_page($html);

subtest "man page transformation" => sub {
    # test some data items
    is($data->{element_list}[0],'Host', "first element name");
    is($data->{element_list}[5],'BindAddress', "5th element name");

    my $param_data=$data->{element_data}{'VerifyHostKeyDNS'};
    is($param_data->[0],'B<VerifyHostKeyDNS>','check B<> transformation in parameter name');
    like($param_data->[1],qr/B<yes>/,'check B<> transformation in parameter description');
    is($param_data->[2],"See also\nI<VERIFYING HOST KEYS> in L<ssh(1)>.", "check I<> and L<> transformation");
};

subtest "test generation of model string" => sub {
    my @unilines = qw/Host Match ControlPersist DynamicForward GlobalKnownHostsFile/;

    my %expected_load = (
        AddKeysToAgent => 'type=leaf value_type=enum choice=yes,confirm,ask,no upstream_default=no',
        AddressFamily => 'type=leaf value_type=enum choice=any,inet,inet6 upstream_default=any',
        BatchMode => 'type=leaf value_type=boolean write_as=no,yes upstream_default=no',
        CanonicalizeFallbackLocal => 'type=leaf value_type=boolean write_as=no,yes upstream_default=yes',
        CanonicalizeHostname => 'type=leaf value_type=enum choice=no,yes,always upstream_default=no',
        CanonicalizeMaxDots => 'type=leaf value_type=integer upstream_default=1',
        CheckHostIP => 'type=leaf value_type=boolean write_as=no,yes upstream_default=yes',
        ConnectionAttempts => 'type=leaf value_type=integer upstream_default=1',
        ConnectTimeout => 'type=leaf value_type=integer',
        ControlMaster => 'type=leaf value_type=enum choice=auto,autoask,yes,no,ask upstream_default=no',
        ExitOnForwardFailure => 'type=leaf value_type=boolean write_as=no,yes upstream_default=no',
        ForwardX11Timeout => 'type=leaf value_type=integer',
        GSSAPIAuthentication => 'type=leaf value_type=boolean write_as=no,yes upstream_default=no',
    );

    foreach my $p (@unilines) {
        $expected_load{$p} = 'type=leaf value_type=uniline';
    }

    foreach my $param ($data->{element_list}->@*) {
        my @desc = $data->{element_data}{$param}->@*;

        # check only some of the parameters
        if (defined  $expected_load{$param}) {
            my $load = create_load_data($param => @desc);
            note("test failed with @desc") unless $load eq $expected_load{$param};
            is($load, $expected_load{$param}, "check generated load string of $param");
        }
    }
}
