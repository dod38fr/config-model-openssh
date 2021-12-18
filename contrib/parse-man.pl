#!/usr/bin/perl

use strict;
use warnings;
use 5.22.0;
use utf8;

use lib 'contrib/lib';

use IO::Pipe;
use Path::Tiny;
use Config::Model 2.134; # load_data __skip_order parameter
use Config::Model::Itself 2.012;
use Config::Model::Exception;
use YAML::XS qw/LoadFile/;

use experimental qw/postderef signatures/ ;

use ParseMan;

# make sure that Ssh models are created from scratch
path('lib/Config/Model/models/')->remove_tree;

sub parse_man_page ($man_page_name) {
    my $pipe = IO::Pipe->new();
    $pipe->reader("roff2html $man_page_name");
    my @lines = $pipe->getlines;
    $pipe->close;
    return parse_html_man_page(join('',@lines));
}

sub store_description ($obj, @desc) {
    shift @desc; # remove keyword
    $obj->fetch_element("description")->store(join("\n\n", @desc));
}

sub create_ssh_model ($meta_root) {
    say "Processing ssh documentation...";

    create_class_boilerplate ($meta_root, ssh_system => 'Ssh');
    create_class_boilerplate ($meta_root, ssh_system => 'Ssh::HostElement');

    # extract data from ssh man pages
    my $data = parse_man_page( 'ssh_config' ) ;

    foreach my $element ($data->{element_list}->@*) {
        my @desc = $data->{element_data}{$element}->@*;
        my $load_string = create_load_data(ssh => $element, @desc);
        my $target = $element =~ /^(Host|Match)$/ ? 'Ssh' : 'Ssh::HostElement';
        my $obj = $meta_root->grab(qq!class:$target element:"$element"!);
        $obj->load($load_string);
        store_description($obj, @desc);
    }

    $meta_root->load(qq!class:Ssh include="Ssh::HostElement"!);
}

sub create_sshd_model ($meta_root) {
    say "Processing sshd documentation...";

    create_class_boilerplate ($meta_root, sshd_system => 'Sshd');
    create_class_boilerplate ($meta_root, sshd_system => 'Sshd::MatchElement');

    my $data = parse_man_page( 'sshd_config' ) ;

    # retrieve list of keywords that can fit in Match block
    my $is_match = extract_list_from_desc($data->{element_data}{'Match'});

    foreach my $element ($data->{element_list}->@*) {
        my @desc = $data->{element_data}{$element}->@*;
        my $load_string = create_load_data(sshd => $element, @desc);
        my $target = $is_match->{$element} ? 'Sshd::MatchElement' : 'Sshd';
        my $obj = $meta_root->grab(qq!class:$target element:"$element"!);
        $obj->load($load_string);
        store_description($obj, @desc);
    }

    $meta_root->load(qq!class:Sshd include="Sshd::MatchElement"!);
}

sub extract_list_from_desc ($desc_ref) {
    my $str = $desc_ref->[$#$desc_ref];
    my @keywords = ( $str =~ /B<(\w+)>/g );
    my %is_match = map { $_ => 1 ; } grep { $_ ne 'Match' } @keywords;
    return \%is_match;
}

sub load_yaml_model ($meta_root,$class) {
    my $file = 'contrib/'.lc($class).'.yml';
    $file =~ s/::/-/g;
    say "Creating $class from $file...";
    $meta_root->load_data(LoadFile($file));
}

# Itself constructor returns an object to read or write the data
# structure containing the model to be edited
my $rw_obj = Config::Model::Itself -> new () ;

# now load the existing model to be edited
$rw_obj -> read_all() ;
my $meta_root = $rw_obj->meta_root;

load_yaml_model($meta_root,"Ssh::PortForward");

say "Creating ssh model...";
create_ssh_model($meta_root);

say "loading ssh model addendum from ssh-fixup.yaml";
$meta_root->load_data(LoadFile('contrib/ssh-fixup.yaml'));

say "loading ssh model IPQoS element from fixup-element-ipqos.yml";
$meta_root
    ->grab("class:Ssh::HostElement element:IPQoS")
    ->load_data(LoadFile('contrib/fixup-element-ipqos.yml'));

# This class include Ssh model and must be loaded after Ssh model is
# created
load_yaml_model($meta_root,"SystemSsh");

say "Ssh model is done...";

say "Generating Sshd model";

load_yaml_model($meta_root,"Sshd::MatchCondition");

create_sshd_model($meta_root);

# requires Sshd::MatchElement
load_yaml_model($meta_root,"Sshd::MatchBlock");

say "loading sshd model addendum from sshd-fixup.yaml";
$meta_root->load_data(LoadFile('contrib/sshd-fixup.yaml'));

say "loading ssh model IPQoS element from fixup-element-ipqos.yml";
$meta_root
    ->grab("class:Sshd::MatchElement element:IPQoS")
    ->load_data(LoadFile('contrib/fixup-element-ipqos.yml'));

say "Saving ssh and sshd models...";
$rw_obj->write_all;

say "Done.";
