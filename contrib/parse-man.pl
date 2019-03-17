#!/usr/bin/perl

use strict;
use warnings;
use 5.22.0;
use utf8;

use lib 'contrib/lib';

use IO::Pipe;
use Path::Tiny;
use Config::Model::Itself 2.012;
use Config::Model::Exception;
use Getopt::Long;
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

sub create_ssh_model ($meta_root) {
    say "Processing ssh documentation...";

    create_class_boilerplate ($meta_root, ssh_system => 'Ssh');
    create_class_boilerplate ($meta_root, ssh_system => 'Ssh::HostElement');

    # extract data from ssh man pages
    my $data = parse_man_page( 'ssh_config' ) ;

    foreach my $element ($data->{element_list}->@*) {
        my @desc = $data->{element_data}{$element}->@*;
        my $load_string = create_load_data(ssh => $element, @desc);
        my $target = $element =~ /^Host|Match$/ ? 'Ssh' : 'Ssh::HostElement';
        my $obj = $meta_root->grab(qq!class:$target element:"$element"!);
        $obj->load($load_string);
        $obj->fetch_element("description")->store(join('', @desc));
    }

    $meta_root->load(qq!class:Ssh include="Ssh::HostElement"!);
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

$meta_root->load( << 'EOCDS' );
class:Ssh::HostElement
  element:IdentityFile
    cargo
      warn_if_match:"\.pub$"
        msg="identity file should be the private key file"
        fix=s/\.pub$//; - - -
  element:IPQoS
    assert:1_or_2
      code="return 1 unless defined $_; my @v = (/(\w+)/g); return (@v < 3) ? 1 : 0; "
      msg="value must not have more than 2 fields." -
    assert:accepted_values
      code="return 1 unless defined $_;
            my @v = (/(\S+)/g);
            my @good = grep {/^(af[1-4][1-3]|cs[0-7]|ef|lowdelay|throughput|reliability|none|\d+)/} @v ;
            return @good == @v ? 1 : 0; "
      msg="value must be 1 or 2 occurences of: 'af11', 'af12', 'af13', 'af21', 'af22',
'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs0', 'cs1',
'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef', 'lowdelay',
'throughput', 'reliability', 'none' or a numeric value." -
EOCDS

# This class include Ssh model and must be loaded after Ssh model is
# created
load_yaml_model($meta_root,"SystemSsh");

say "Saving ssh model...";
$rw_obj->write_all;

say "Done.";
