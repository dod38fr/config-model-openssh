package Config::Model::Backend::OpenSsh::Sshd ;

use Mouse ;
extends "Config::Model::Backend::Any" ;

with (
    'Config::Model::Backend::OpenSsh::Role::Reader',
    'Config::Model::Backend::OpenSsh::Role::Writer',
);

use Carp ;
use IO::File ;
use Log::Log4perl;
use File::Copy ;
use File::Path ;

my $logger = Log::Log4perl::get_logger("Backend::OpenSsh");

# now the write part
sub write {
    my $self = shift;
    $self->ssh_write(@_) ;
}

sub _write_line {
    return sprintf("%-20s %s\n",@_) ;
}


no Mouse;

1;

# ABSTRACT: Backend for sshd configuration files

__END__

=head1 SYNOPSIS

None

=head1 DESCRIPTION

This class provides a backend to read and write sshd client configuration files.

This class is a plugin for L<Config::Model::BackendMgr>.

=head1 SEE ALSO

L<cme>, L<Config::Model>,
