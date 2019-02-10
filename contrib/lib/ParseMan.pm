package ParseMan;

# This module is used by parse_man.pl to generate Ssh models
# and should not be shippped to CPAN

use strict;
use warnings;

use 5.22.0;
use utf8;

use lib qw(lib contrib/lib);
use experimental qw/postderef signatures/ ;
use XML::Twig;

use Exporter 'import';

our @EXPORT = qw(parse_html_man_page);

sub parse_html_man_page ($html_man_page) {

    my %data = (
        element_list => [],
        element_data => {},
    );
    my $config_class;
    my $parameter ;
    my $param_text ;

    my $manpage = sub ($t, $elt) {
        my $man = $elt->first_child('refentrytitle')->text;
        my $nb = $elt->first_child('manvolnum')->text;
        $elt->set_text( qq!L<$man($nb)>!);
    };

    my $turn_to_pod_c = sub { my $t = $_->text(); $_->set_text("C<$t>");};

    my $ssh_param = sub {
        # remove B<> that was added by a twig_handler
        ($parameter) = ($_->text() =~ /B<(\w+)>/);
        push $data{element_list}->@*, $parameter;
        $data{element_data}{$parameter} = [];
    };

    my $ssh_data = sub {
        my $text = $_->text();
        $text =~ s/([\w-]+)\((\d+)\)/L<$1($2)>/g;
        push $data{element_data}{$parameter}->@*, $text if $parameter;
    };

    my $twig = XML::Twig->new (
        twig_handlers => {
            'html/body/p[@style="margin-top: 1em"]/[string(b)=~ /^[A-Z]+[a-z]/]'
                => $ssh_param,
            # try to stop at the section after the parameter list
            'html/body/p[@style="margin-top: 1em"]/[string(b)=~ /^[A-Z\s]+$/]'
                => sub { $parameter = '';},
            'html/body/p' => $ssh_data,
            'b' => sub { my $t = $_->text; $_->set_text("B<$t>")},
            'i' => sub { my $t = $_->text; $_->set_text("I<$t>")},
        }
    );

    $twig->parse_html($html_man_page);
    return \%data;
}

1;
