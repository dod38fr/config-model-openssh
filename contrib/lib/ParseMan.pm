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

our @EXPORT = qw(parse_html_man_page create_load_data);


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

sub setup_choice {
    my (@choices, %choice_hash) ;

    return (
        sub {
            foreach my $v (@_) {
                next if $choice_hash{$v};
                push @choices, $v;
                $choice_hash{$v} = 1;
            }
        },
        sub { return @choices;}
    );
}

my %override = (
    # description is too complex to parse
    ControlPersist => 'type=leaf value_type=uniline',
);

sub create_load_data ($name, @desc) {
    my @log;
    my $bold_name = shift @desc; # drop '<b>Keyword</b>'
    my $desc = join('', @desc);

    return $override{$name} if $override{$name};

    # trim description (which is not saved in this sub) to simplify
    # the regexp below
    $desc =~ s/[\s\n]+/ /g;
    my ($default, %choice_hash, $value_type);
    my @load ;
    my @load_extra;
    my ($set_choice, $get_choices) = setup_choice();

    # handle "The argument must be B<yes>, B<no> (the default) or B<ask>."
    if ($desc =~ /(?:argument|option)s? (?:are|must be)([^.]+)\./i) {
        my $str = $1;
        $set_choice->( $str =~ /B<([\w]+)>/g );
    }

    if (my @values = ($desc =~ /(?:(?:if|when|with) (?:(?:$bold_name|the option) (?:is )?)?set to|A value of|setting this to|The default(?: is|,)) B<(\w+)>/gi)) {
        $set_choice->(@values);
    }

    my @choices = $get_choices->();
    if (@choices == 1 and $choices[0] eq 'no') {
        # assume the other choice is 'yes'
        push @choices, 'yes';
    }

    if ($desc =~ /Specif\w+ (\w+ ){0,2}(number|timeout)/) {
        $value_type = 'integer';
        if ($desc =~ /The default(?: is|,) (\d+)/) {
            push @load_extra, "upstream_default=$1";
        }
    }
    elsif (@choices == 2 and grep { /^yes|no$/ } @choices) {
        $value_type = 'boolean';
        push @load_extra, 'write_as=no,yes';
    }
    elsif (@choices) {
        $value_type = 'enum';
        push @load_extra, 'choice='.join(',',@choices);
    }

    if ($desc =~ /The default(?: is|,) B<(\w+)>/ or $desc =~ /B<([\w]+)> \(the default\)/) {
        push @load_extra, "upstream_default=$1";
    }

    $value_type //= 'uniline';

    push @load, 'type=leaf', "value_type=$value_type";

    return join(' ',@load, @load_extra);
}

1;
