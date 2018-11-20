package Config::Model::OpenSsh ;

use Config::Model 2.111;

1;

# ABSTRACT: OpenSSH config editor

__END__

=head1 SYNOPSIS

=head2 invoke editor

The following will launch a graphical editor (if L<Config::Model::TkUI>
is installed):

 sudo cme edit sshd 

=head2 command line

This command will add a C<Host Foo> section in C<~/.ssh/config>: 

 cme modify ssh Host:Foo ForwardX11=yes
 
=head2 programmatic

This code snippet will remove the C<Host Foo> section added above:

 use Config::Model ;
 my $model = Config::Model -> new ( ) ;
 my $inst = $model->instance (root_class_name => 'Ssh');
 $inst -> config_root ->load("Host~Foo") ;
 $inst->write_back() ;

=head1 DESCRIPTION

This module provides a configuration editors (and models) for the 
configuration files of OpenSSH. (C</etc/ssh/sshd_config>, F</etc/ssh/ssh_config>
and C<~/.ssh/config>).

This module can also be used to modify safely the
content of these configuration files from a Perl programs.

Once this module is installed, you can edit C</etc/ssh/sshd_config> 
with run (as root) :

 # cme edit sshd 

To edit F</etc/ssh/ssh_config>, run (as root):

 # cme edit ssh

To edit F<~/.ssh/config>, run as a normal user:

 $ cme edit ssh

=head1 user interfaces

As mentioned in L<cme>, several user interfaces are available with C<edit> subcommand:

=over

=item *

A graphical interface is proposed by default if L<Config::Model::TkUI> is installed.

=item *

A Curses interface with option C<cme edit ssh -ui curses> if L<Config::Model::CursesUI> is installed.

=item *

A Shell like interface with option C<cme edit ssh -ui shell>.

=back

=head1 SEE ALSO

L<cme>, L<Config::Model>,
