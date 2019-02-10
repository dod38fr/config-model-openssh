use strict;
use warnings;
use lib qw(contrib/lib);
use 5.22.0;

use ParseMan;

use Test::More;
use Test::Differences;
use Path::Tiny;

my $html = path('xt/ssh.html')->slurp;

my $data = parse_html_man_page($html);

# test some data items
is($data->{element_list}[0],'Host', "first element name");
is($data->{element_list}[5],'BindAddress', "5th element name");

my $param_data=$data->{element_data}{'VerifyHostKeyDNS'};
is($param_data->[0],'B<VerifyHostKeyDNS>','check B<> transformation in parameter name');
like($param_data->[1],qr/B<yes>/,'check B<> transformation in parameter description');
is($param_data->[2],"See also\nI<VERIFYING HOST KEYS> in L<ssh(1)>.", "check I<> and L<> transformation");

