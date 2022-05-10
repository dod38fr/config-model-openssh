use strict;
use warnings;

return [
  {
    'accept' => [
      '.*',
      {
        'summary' => 'boilerplate parameter that may hide a typo',
        'type' => 'leaf',
        'value_type' => 'uniline',
        'warn' => 'Unknown parameter. Please make sure there\'s no typo and contact the author'
      }
    ],
    'class_description' => 'This configuration class was generated from ssh_system documentation.
by L<parse-man.pl|https://github.com/dod38fr/config-model-openssh/contrib/parse-man.pl>
',
    'element' => [
      'Host',
      {
        'cargo' => {
          'config_class_name' => 'Ssh::HostElement',
          'type' => 'node'
        },
        'description' => 'Restricts the
following declarations (up to the next B<Host> or
B<Match> keyword) to be only for those hosts that match
one of the patterns given after the keyword. If more than
one pattern is provided, they should be separated by
whitespace. A single \'*\' as a pattern can be
used to provide global defaults for all hosts. The host is
usually the I<hostname> argument given on the command
line (see the B<CanonicalizeHostname> keyword for
exceptions).

A pattern entry
may be negated by prefixing it with an exclamation mark
(\'!\'). If a negated entry is matched, then the
B<Host> entry is ignored, regardless of whether any
other patterns on the line match. Negated matches are
therefore useful to provide exceptions for wildcard
matches.

See
I<PATTERNS> for more information on patterns.',
        'index_type' => 'string',
        'ordered' => '1',
        'type' => 'hash'
      },
      'Match',
      {
        'cargo' => {
          'config_class_name' => 'Ssh::HostElement',
          'type' => 'node'
        },
        'description' => 'Restricts the
following declarations (up to the next B<Host> or
B<Match> keyword) to be used only when the conditions
following the B<Match> keyword are satisfied. Match
conditions are specified using one or more criteria or the
single token B<all> which always matches. The available
criteria keywords are: B<canonical>, B<final>,
B<exec>, B<host>, B<originalhost>, B<user>,
and B<localuser>. The B<all> criteria must appear
alone or immediately after B<canonical> or B<final>.
Other criteria may be combined arbitrarily. All criteria but
B<all>, B<canonical>, and B<final> require an
argument. Criteria may be negated by prepending an
exclamation mark (\'!\').

The
B<canonical> keyword matches only when the configuration
file is being re-parsed after hostname canonicalization (see
the B<CanonicalizeHostname> option). This may be useful
to specify conditions that work with canonical host names
only.

The
B<final> keyword requests that the configuration be
re-parsed (regardless of whether B<CanonicalizeHostname>
is enabled), and matches only during this final pass. If
B<CanonicalizeHostname> is enabled, then
B<canonical> and B<final> match during the same
pass.

The B<exec>
keyword executes the specified command under the
user\'s shell. If the command returns a zero exit
status then the condition is considered true. Commands
containing whitespace characters must be quoted. Arguments
to B<exec> accept the tokens described in the
I<TOKENS> section.

The other
keywords\' criteria must be single entries or
comma-separated lists and may use the wildcard and negation
operators described in the I<PATTERNS> section. The
criteria for the B<host> keyword are matched against the
target hostname, after any substitution by the
B<Hostname> or B<CanonicalizeHostname> options. The
B<originalhost> keyword matches against the hostname as
it was specified on the command-line. The B<user>
keyword matches against the target username on the remote
host. The B<localuser> keyword matches against the name
of the local user running L<ssh(1)> (this keyword may be useful
in system-wide B<ssh_config> files).',
        'index_type' => 'string',
        'ordered' => '1',
        'type' => 'hash'
      }
    ],
    'generated_by' => 'parse-man.pl from ssh_system  9.0p1 doc',
    'include' => [
      'Ssh::HostElement'
    ],
    'include_after' => 'Host',
    'license' => 'LGPL2',
    'name' => 'Ssh',
    'rw_config' => {
      'auto_create' => '1',
      'backend' => 'OpenSsh::Ssh',
      'config_dir' => '~/.ssh',
      'file' => 'config'
    }
  }
]
;

