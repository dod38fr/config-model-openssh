use strict;
use warnings;

package ParseMan;

# This module is used by parse_man.pl to generate Ssh models
# and should not be shippped to CPAN

use 5.22.0;
use utf8;
use English;

use lib qw(lib contrib/lib);
use experimental qw/postderef signatures/ ;
use XML::Twig;
use List::MoreUtils qw/any/;
use Text::Wrap;
$Text::Wrap::columns = 80;

use Exporter 'import';

our @EXPORT = qw(parse_html_man_page create_load_data create_class_boilerplate);

sub parse_html_man_page ($html_man_page) {

    my %data = (
        element_list => [],
        element_data => {},
    );
    my $config_class;
    my $parameter ;

    my $manpage = sub ($t, $elt) {
        my $man = $elt->first_child('refentrytitle')->text;
        my $nb = $elt->first_child('manvolnum')->text;
        $elt->set_text( qq!L<$man($nb)>!);
    };

    my $turn_to_pod_c = sub { my $t = $_->text(); $_->set_text("C<$t>");};

    my $ssh_param = sub {
        $parameter = $_->text();
        $parameter =~ s/\s//g;
        say "Found parameter «$parameter»";
        push $data{element_list}->@*, $parameter;
        $data{element_data}{$parameter} = [];
    };

    my $store_ssh_data = sub ($text) {
        $text =~ s/([\w-]+)\((\d+)\)/L<$1($2)>/g;
        # replace utf-8 quotes with B<>
        $text =~ s/\x{201c}(\w+)\x{201d}/B<$1>/g;
        # replace single utf-8 quote with ascii quote
        $text =~ s/\x{2019}/'/g;
        # replace backquote with quote
        $text =~ s/`/'/g;
        # avoid long unbreakable lines
        $text =~ s/,(\w)/, $1/g;
        # avoid leading whitespace
        $text =~ s/^\s+//mg;
        # avoid trailing whitespace
        $text =~ s/\s+$//mg;
        # convert a roff tag missed by man2html
        $text =~ s/^Sx\s(.*)$/I<$1>/mg;
        # put text in a single line (roff conversion lead to a lot of \n)
        $text =~ s/\n+/ /g;
        $text =~ s/\s*<<>>\s*/\n\n/g;
        my $desc = fill('','', $text);
        push $data{element_data}{$parameter}->@*, $desc if $parameter;
    };

    my $buggy_ssh_param = sub {
        # a bug in man2html sometimes (for
        # CanonicalizePermittedCNAMEs) adds part of the description in
        # DT element outside of <B>
        my $desc_part = $_->text();
        # remove B<> that was handled by $ssh_param
        $desc_part =~ s!B<.*>\s*!!i;
        $store_ssh_data->($desc_part) if $desc_part;
    };

    my $ssh_data = sub {
        $store_ssh_data->($_->text());
    };

    my $twig = XML::Twig->new;

    my $handlers = {
            'html/body/h2' => sub {
                # de-installing handler at the end of DESCRIPTION section
                $twig->setTwigHandlers({});
            },
            'html/body/p/dl/dt/b' => $ssh_param,
            'html/body/p/dl/dt' => $buggy_ssh_param,
            'html/body/p/dl/dd' => $ssh_data,
            'b' => sub { my $t = $_->text; $t =~ s/^\s+|\s+$//g; $_->set_text("B<$t> ")},
            'i' => sub { my $t = $_->text; $_->set_text("I<$t> ")},
            'p' => sub { my $t = $_->text; $_->set_text("\n<<>>\n$t")},
        };

    $twig->setTwigHandlers({
        'html/body/h2[string() = "DESCRIPTION"]' => sub {
            # installing handler";
            $twig->setTwigHandlers($handlers);
        }
    });

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

my $ssh_host = 'type=hash index_type=string ordered=1 cargo type=node '
    .'config_class_name=Ssh::HostElement';
my $ssh_forward = 'type=list cargo type=node config_class_name="Ssh::PortForward"';
my $uniline = 'type=leaf value_type=uniline';
my $uniline_list = "type=list cargo $uniline";
my $yes_no_leaf = "type=leaf value_type=boolean write_as=no,yes";
my %override = (
    all => {
        IPQoS => 'type=leaf value_type=uniline upstream_default="af21 cs1"',
        KbdInteractiveAuthentication => "$yes_no_leaf upstream_default=yes",
    },
    ssh => {
        # description is too complex to parse
        EscapeChar => $uniline,
        ControlPersist => $uniline,
        GlobalKnownHostsFile => $uniline.' default="/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2"',
        Host => $ssh_host,
        IdentityFile => $uniline_list,
        LocalForward => $ssh_forward,
        Match => $ssh_host,
        StrictHostKeyChecking => 'type=leaf value_type=enum '
           . 'choice=yes,accept-new,no,off,ask upstream_default=ask',
        UserKnownHostsFile => "$uniline_list",
        KbdInteractiveDevices => $uniline_list,
        PreferredAuthentications => $uniline_list,
        RemoteForward => $ssh_forward,
    },
    sshd => {
        AuthenticationMethods => $uniline,
        AuthorizedKeysFile => $uniline_list,
        AuthorizedPrincipalsFile => 'type=leaf value_type=uniline upstream_default="none"',
        ChrootDirectory => 'type=leaf value_type=uniline upstream_default="none"',
        ForceCommand => 'type=leaf value_type=uniline upstream_default="none"',
        GSSAPIStoreCredentialsOnRekey => "$yes_no_leaf upstream_default=no",
        IgnoreUserKnownHosts => "$yes_no_leaf upstream_default=no",
        MaxStartups => 'type=leaf value_type=uniline upstream_default=10',
        PAMServiceName => 'type=leaf value_type=uniline level=hidden ' .
        # this parameter shows up only when UsePAM is true
        'warp follow:use_pam="- UsePAM" rules:"$use_pam" level=normal',
        PasswordAuthentication => 'type=leaf value_type=uniline upstream_default=sshd',
        Subsystem => 'type=hash index_type=string '
            . 'cargo type=leaf value_type=uniline mandatory=1 - - ',
        VersionAddendum => $uniline,
    }
);

sub create_load_data ($ssh_system, $name, @desc) {
    my $desc = join('', @desc);

    if ($override{$ssh_system}{$name}) {
        say "Parameter $ssh_system $name is overridden";
        return $override{$ssh_system}{$name};
    }
    if ($override{'all'}{$name}) {
        say "Parameter $ssh_system $name is overridden in ssh and sshd";
        return $override{'all'}{$name};
    }

    say "Parameter $ssh_system $name: analysing description";

    # trim description (which is not saved in this sub) to simplify
    # the regexp below
    $desc =~ s/[\s\n]+/ /g;
    my (%choice_hash, $value_type);
    my @load_extra;
    my ($set_choice, $get_choices) = setup_choice();

    # handle "The argument must be B<yes>, B<no> (the default) or B<ask>"
    # since man2html is used, dot after B<> are no longer found.
    if ($desc =~ /(?:argument|option)s? (?:to this keyword )?(?:are|\w+ be)(?: one of)?(?:[\s:]+)(?=B<)([^.]+)/i) {
        my $str = $1;
        $set_choice->( $str =~ /(?<!-)B<(\w[\w-]*)>/g );
    }

    if ($desc =~ /supported keywords are(?:[\s:]+)(?=B<)([^.]+)\./i) {
        my $str = $1;
        $set_choice->( $str =~ /B<(\w[\w-]*)>/g );
    }

    if (my @values = ($desc =~ /(?:(?:if|when|with) (?:(?:B<$name>|th(?:e|is) option) (?:is )?)?set to|A value of|setting this to|The default(?: is|,)|Accepted values are) B<([a-z]\w+)>/gi)) {
        $set_choice->(@values);
    }

    if (my @values = ($desc =~ /The possible values are:([^.]+)\./gi)) {
        my $str = $1;
        $set_choice->( $str =~ /([A-Z\d]+)/g );
    }

    my @choices = $get_choices->();
    if (@choices == 1 and $choices[0] eq 'no') {
        # assume the other choice is 'yes'
        push @choices, 'yes';
    }
    if (@choices == 1 and $choices[0] eq 'yes') {
        push @choices, 'no';
    }

    if ($desc =~ /(Specif\w+|Sets?) (a|the) (maximum )?(number|timeout)|size \(in bits\)/) {
        my $upstream_default;
        if ($desc =~ /The default(?: value)?(?: is|,) (\d+)/) {
            $upstream_default = $1;
        }
        # do not set integer type when upstream default value is not an integer
        if (not defined $upstream_default or $upstream_default =~ /^\d+$/) {
            $value_type = 'integer';
            push @load_extra, qq!upstream_default="$upstream_default"! if defined $upstream_default;
        }
    }
    elsif (@choices == 1) {
        die "Parser error: Cannot create an enum with only once choice ($name): @choices\n",
            "Description is:\n $desc\n";
    }
    elsif (@choices == 2 and any { /^yes|no$/ } @choices) {
        $value_type = 'boolean';
        push @load_extra, 'write_as=no,yes';
    }
    elsif (@choices) {
        $value_type = 'enum';
        push @load_extra, 'choice='.join(',',sort @choices);
    }

    if ($desc =~ m!The default(?: is|,) [BI]<([\w/:]+)>! or
            $desc =~ m!The default(?: is|,) ((?:/\w+)+)\b! or
            $desc =~ /The default(?: is|,) ([A-Z]{3,}\d?)\b/ or
            $desc =~ /B<([\w]+)> \(the default\)/) {
        push @load_extra, "upstream_default=$1";
    }

    $value_type //= 'uniline';

    my @load ;
    if ($desc =~ /multiple (\w+ ){1,2}may be (specified|separated)|keyword can be followed by a list of/i) {
        @load = ('type=list', 'cargo');
    }
    # TODO:
    # CanonicalDomains depends on CanonicalizeHostname -> order problem, use move on model

    push @load, 'type=leaf', "value_type=$value_type";

    return join(' ',@load, @load_extra);
}

my ($ssh_version) = (`ssh -V 2>&1` =~ /OpenSSH_([\w\.]+)/);

sub create_class_boilerplate ($meta_root, $ssh_system,  $config_class) {
    my $desc_text="This configuration class was generated from $ssh_system documentation.\n"
        ."by L<parse-man.pl|https://github.com/dod38fr/config-model-openssh/contrib/parse-man.pl>\n";

    my $steps = "class:$config_class class_description";
    $meta_root->grab(step => $steps, autoadd => 1)->store($desc_text);

    $meta_root->load( steps => [
        qq!class:$config_class generated_by="parse-man.pl from $ssh_system  $ssh_version doc"!,
        qq!license=LGPL2!,
        qq!accept:".*" type=leaf value_type=uniline!,
        qq!summary="boilerplate parameter that may hide a typo"!,
        qq!warn="Unknown parameter. Please make sure there\'s no typo and contact the author"!,
    ]);
}

1;
