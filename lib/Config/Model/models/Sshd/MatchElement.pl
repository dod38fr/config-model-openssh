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
    'class_description' => 'This configuration class was generated from sshd_system documentation.
by L<parse-man.pl|https://github.com/dod38fr/config-model-openssh/contrib/parse-man.pl>
',
    'element' => [
      'AcceptEnv',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies what environment variables sent by the client will be copied into the
session\'s L<environ(7)>. See B<SendEnv> and B<SetEnv> in ssh_config5 for how to
configure the client. The B<TERM> environment variable is always accepted
whenever the client requests a pseudo-terminal as it is required by the
protocol. Variables are specified by name, which may contain the wildcard
characters \'*\' and \'?\' Multiple environment variables may be separated by
whitespace or spread across multiple B<AcceptEnv> directives. Be warned that
some environment variables could be used to bypass restricted user
environments. For this reason, care should be taken in the use of this
directive. The default is not to accept any environment variables.',
        'type' => 'list'
      },
      'AllowAgentForwarding',
      {
        'description' => 'Specifies whether ssh-agent1 forwarding is permitted. The default is B<yes>
Note that disabling agent forwarding does not improve security unless users are
also denied shell access, as they can always install their own forwarders.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'AllowGroups',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'This keyword can be followed by a list of group name patterns, separated by
spaces. If specified, login is allowed only for users whose primary group or
supplementary group list matches one of the patterns. Only group names are
valid; a numerical group ID is not recognized. By default, login is allowed for
all groups. The allow/deny groups directives are processed in the following
order: B<DenyGroups> B<AllowGroups>

See PATTERNS in ssh_config5 for more information on patterns. This keyword may
appear multiple times in B<sshd_config> with each instance appending to the
list.',
        'type' => 'list'
      },
      'AllowStreamLocalForwarding',
      {
        'choice' => [
          'all',
          'local',
          'no',
          'remote',
          'yes'
        ],
        'description' => 'Specifies whether StreamLocal (Unix-domain socket) forwarding is permitted. The
available options are B<yes> (the default) or B<all> to allow StreamLocal
forwarding, B<no> to prevent all StreamLocal forwarding, B<local> to allow
local (from the perspective of L<ssh(1)>) forwarding only or B<remote> to allow
remote forwarding only. Note that disabling StreamLocal forwarding does not
improve security unless users are also denied shell access, as they can always
install their own forwarders.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'enum'
      },
      'AllowTcpForwarding',
      {
        'choice' => [
          'all',
          'local',
          'no',
          'remote',
          'yes'
        ],
        'description' => 'Specifies whether TCP forwarding is permitted. The available options are B<yes>
(the default) or B<all> to allow TCP forwarding, B<no> to prevent all TCP
forwarding, B<local> to allow local (from the perspective of L<ssh(1)>)
forwarding only or B<remote> to allow remote forwarding only. Note that
disabling TCP forwarding does not improve security unless users are also denied
shell access, as they can always install their own forwarders.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'enum'
      },
      'AllowUsers',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'This keyword can be followed by a list of user name patterns, separated by
spaces. If specified, login is allowed only for user names that match one of
the patterns. Only user names are valid; a numerical user ID is not recognized.
By default, login is allowed for all users. If the pattern takes the form
USER@HOST then USER and HOST are separately checked, restricting logins to
particular users from particular hosts. HOST criteria may additionally contain
addresses to match in CIDR address/masklen format. The allow/deny users
directives are processed in the following order: B<DenyUsers> B<AllowUsers>

See PATTERNS in ssh_config5 for more information on patterns. This keyword may
appear multiple times in B<sshd_config> with each instance appending to the
list.',
        'type' => 'list'
      },
      'AuthenticationMethods',
      {
        'description' => 'Specifies the authentication methods that must be successfully completed for a
user to be granted access. This option must be followed by one or more lists of
comma-separated authentication method names, or by the single string B<any> to
indicate the default behaviour of accepting any single authentication method.
If the default is overridden, then successful authentication requires
completion of every method in at least one of these lists.

For example, Qq publickey, password publickey, keyboard-interactive would
require the user to complete public key authentication, followed by either
password or keyboard interactive authentication. Only methods that are next in
one or more lists are offered at each stage, so for this example it would not
be possible to attempt password or keyboard-interactive authentication before
public key.

For keyboard interactive authentication it is also possible to restrict
authentication to a specific device by appending a colon followed by the device
identifier B<bsdauth> or B<pam> depending on the server configuration. For
example, Qq keyboard-interactive:bsdauth would restrict keyboard interactive
authentication to the B<bsdauth> device.

If the publickey method is listed more than once, L<sshd(8)> verifies that keys
that have been used successfully are not reused for subsequent authentications.
For example, Qq publickey, publickey requires successful authentication using
two different public keys.

Note that each authentication method listed should also be explicitly enabled
in the configuration.

The available authentication methods are: Qq gssapi-with-mic , Qq hostbased ,
Qq keyboard-interactive , Qq none (used for access to password-less accounts
when B<PermitEmptyPasswords> is enabled), Qq password and Qq publickey .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'AuthorizedKeysCommand',
      {
        'description' => 'Specifies a program to be used to look up the user\'s public keys. The program
must be owned by root, not writable by group or others and specified by an
absolute path. Arguments to B<AuthorizedKeysCommand> accept the tokens
described in the I<TOKENS> section. If no arguments are specified then the
username of the target user is used.

The program should produce on standard output zero or more lines of
authorized_keys output (see I<AUTHORIZED_KEYS> in L<sshd(8)>).
B<AuthorizedKeysCommand> is tried after the usual B<AuthorizedKeysFile> files
and will not be executed if a matching key is found there. By default, no
B<AuthorizedKeysCommand> is run.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'AuthorizedKeysCommandUser',
      {
        'description' => 'Specifies the user under whose account the B<AuthorizedKeysCommand> is run. It
is recommended to use a dedicated user that has no other role on the host than
running authorized keys commands. If B<AuthorizedKeysCommand> is specified but
B<AuthorizedKeysCommandUser> is not, then L<sshd(8)> will refuse to start.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'AuthorizedKeysFile',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies the file that contains the public keys used for user authentication.
The format is described in the AUTHORIZED_KEYS FILE FORMAT section of
L<sshd(8)>. Arguments to B<AuthorizedKeysFile> accept the tokens described in
the I<TOKENS> section. After expansion, B<AuthorizedKeysFile> is taken to be an
absolute path or one relative to the user\'s home directory. Multiple files may
be listed, separated by whitespace. Alternately this option may be set to
B<none> to skip checking for user keys in files. The default is Qq
.ssh/authorized_keys .ssh/authorized_keys2 .',
        'migrate_values_from' => '- AuthorizedKeysFile2',
        'type' => 'list'
      },
      'AuthorizedPrincipalsCommand',
      {
        'description' => 'Specifies a program to be used to generate the list of allowed certificate
principals as per B<AuthorizedPrincipalsFile> The program must be owned by
root, not writable by group or others and specified by an absolute path.
Arguments to B<AuthorizedPrincipalsCommand> accept the tokens described in the
I<TOKENS> section. If no arguments are specified then the username of the
target user is used.

The program should produce on standard output zero or more lines of
B<AuthorizedPrincipalsFile> output. If either B<AuthorizedPrincipalsCommand> or
B<AuthorizedPrincipalsFile> is specified, then certificates offered by the
client for authentication must contain a principal that is listed. By default,
no B<AuthorizedPrincipalsCommand> is run.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'AuthorizedPrincipalsCommandUser',
      {
        'description' => 'Specifies the user under whose account the B<AuthorizedPrincipalsCommand> is
run. It is recommended to use a dedicated user that has no other role on the
host than running authorized principals commands. If
B<AuthorizedPrincipalsCommand> is specified but
B<AuthorizedPrincipalsCommandUser> is not, then L<sshd(8)> will refuse to
start.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'AuthorizedPrincipalsFile',
      {
        'description' => 'Specifies a file that lists principal names that are accepted for certificate
authentication. When using certificates signed by a key listed in
B<TrustedUserCAKeys> this file lists names, one of which must appear in the
certificate for it to be accepted for authentication. Names are listed one per
line preceded by key options (as described in I<AUTHORIZED_KEYS FILE FORMAT> in
L<sshd(8)>). Empty lines and comments starting with \'#\' are ignored.

Arguments to B<AuthorizedPrincipalsFile> accept the tokens described in the
I<TOKENS> section. After expansion, B<AuthorizedPrincipalsFile> is taken to be
an absolute path or one relative to the user\'s home directory. The default is
B<none> i.e. not to use a principals file - in this case, the username of the
user must appear in a certificate\'s principals list for it to be accepted.

Note that B<AuthorizedPrincipalsFile> is only used when authentication proceeds
using a CA listed in B<TrustedUserCAKeys> and is not consulted for
certification authorities trusted via ~/.ssh/authorized_keys though the
B<principals=> key option offers a similar facility (see L<sshd(8)> for
details).',
        'type' => 'leaf',
        'upstream_default' => 'none',
        'value_type' => 'uniline'
      },
      'Banner',
      {
        'description' => 'The contents of the specified file are sent to the remote user before
authentication is allowed. If the argument is B<none> then no banner is
displayed. By default, no banner is displayed.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'CASignatureAlgorithms',
      {
        'description' => 'Specifies which algorithms are allowed for signing of certificates by
certificate authorities (CAs). The default is: ssh-ed25519,
ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521,
sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com, rsa-sha2-512,
rsa-sha2-256

If the specified list begins with a \'+\' character, then the specified
algorithms will be appended to the default set instead of replacing them. If
the specified list begins with a \'-\' character, then the specified algorithms
(including wildcards) will be removed from the default set instead of replacing
them.

Certificates signed using other algorithms will not be accepted for public key
or host-based authentication.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ChannelTimeout',
      {
        'description' => 'Specifies whether and how quickly L<sshd(8)> should close inactive channels.
Timeouts are specified as one or more \'\'type=interval\'\' pairs separated by
whitespace, where the \'\'type\'\' must be the special keyword \'\'global\'\' or a
channel type name from the list below, optionally containing wildcard
characters.

The timeout value \'\'interval\'\' is specified in seconds or may use any of the
units documented in the I<TIME FORMATS> section. For example, \'\'session=5m\'\'
would cause interactive sessions to terminate after five minutes of inactivity.
Specifying a zero value disables the inactivity timeout.

The special timeout \'\'global\'\' applies to all active channels, taken together.
Traffic on any active channel will reset the timeout, but when the timeout
expires then all open channels will be closed. Note that this global timeout is
not matched by wildcards and must be specified explicitly.

The available channel type names include:

B<agent-connection> Open connections to ssh-agent1. B<direct-tcpip ,
direct-streamlocal@openssh.com> Open TCP or Unix socket (respectively)
connections that have been established from a L<ssh(1)> local forwarding, i.e.
B<LocalForward> or B<DynamicForward> B<forwarded-tcpip ,
forwarded-streamlocal@openssh.com> Open TCP or Unix socket (respectively)
connections that have been established to a L<sshd(8)> listening on behalf of a
L<ssh(1)> remote forwarding, i.e. B<RemoteForward> B<session> The interactive
main session, including shell session, command execution, L<scp(1)>,
L<sftp(1)>, etc. B<tun-connection> Open B<TunnelForward> connections.
B<x11-connection> Open X11 forwarding sessions.

Note that in all the above cases, terminating an inactive session does not
guarantee to remove all resources associated with the session, e.g. shell
processes or X11 clients relating to the session may continue to execute.

Moreover, terminating an inactive channel or session does not necessarily close
the SSH connection, nor does it prevent a client from requesting another
channel of the same type. In particular, expiring an inactive forwarding
session does not prevent another identical forwarding from being subsequently
created.

The default is not to expire channels of any type for inactivity.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ChrootDirectory',
      {
        'description' => 'Specifies the pathname of a directory to L<chroot(2)> to after authentication.
At session startup L<sshd(8)> checks that all components of the pathname are
root-owned directories which are not writable by group or others. After the
chroot, L<sshd(8)> changes the working directory to the user\'s home directory.
Arguments to B<ChrootDirectory> accept the tokens described in the I<TOKENS>
section.

The B<ChrootDirectory> must contain the necessary files and directories to
support the user\'s session. For an interactive session this requires at least a
shell, typically L<sh(1)>, and basic /dev nodes such as L<null(4)>, L<zero(4)>,
L<stdin(4)>, L<stdout(4)>, L<stderr(4)>, and L<tty(4)> devices. For file
transfer sessions using SFTP no additional configuration of the environment is
necessary if the in-process sftp-server is used, though sessions which use
logging may require /dev/log inside the chroot directory on some operating
systems (see sftp-server8 for details).

For safety, it is very important that the directory hierarchy be prevented from
modification by other processes on the system (especially those outside the
jail). Misconfiguration can lead to unsafe environments which L<sshd(8)> cannot
detect.

The default is B<none> indicating not to L<chroot(2)>.',
        'type' => 'leaf',
        'upstream_default' => 'none',
        'value_type' => 'uniline'
      },
      'ClientAliveCountMax',
      {
        'description' => 'Sets the number of client alive messages which may be sent without L<sshd(8)>
receiving any messages back from the client. If this threshold is reached while
client alive messages are being sent, sshd will disconnect the client,
terminating the session. It is important to note that the use of client alive
messages is very different from B<TCPKeepAlive> The client alive messages are
sent through the encrypted channel and therefore will not be spoofable. The TCP
keepalive option enabled by B<TCPKeepAlive> is spoofable. The client alive
mechanism is valuable when the client or server depend on knowing when a
connection has become unresponsive.

The default value is 3. If B<ClientAliveInterval> is set to 15, and
B<ClientAliveCountMax> is left at the default, unresponsive SSH clients will be
disconnected after approximately 45 seconds. Setting a zero
B<ClientAliveCountMax> disables connection termination.',
        'type' => 'leaf',
        'upstream_default' => '3',
        'value_type' => 'integer'
      },
      'ClientAliveInterval',
      {
        'description' => 'Sets a timeout interval in seconds after which if no data has been received
from the client, L<sshd(8)> will send a message through the encrypted channel
to request a response from the client. The default is 0, indicating that these
messages will not be sent to the client.',
        'type' => 'leaf',
        'upstream_default' => '0',
        'value_type' => 'integer'
      },
      'DenyGroups',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'This keyword can be followed by a list of group name patterns, separated by
spaces. Login is disallowed for users whose primary group or supplementary
group list matches one of the patterns. Only group names are valid; a numerical
group ID is not recognized. By default, login is allowed for all groups. The
allow/deny groups directives are processed in the following order:
B<DenyGroups> B<AllowGroups>

See PATTERNS in ssh_config5 for more information on patterns. This keyword may
appear multiple times in B<sshd_config> with each instance appending to the
list.',
        'type' => 'list'
      },
      'DenyUsers',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'This keyword can be followed by a list of user name patterns, separated by
spaces. Login is disallowed for user names that match one of the patterns. Only
user names are valid; a numerical user ID is not recognized. By default, login
is allowed for all users. If the pattern takes the form USER@HOST then USER and
HOST are separately checked, restricting logins to particular users from
particular hosts. HOST criteria may additionally contain addresses to match in
CIDR address/masklen format. The allow/deny users directives are processed in
the following order: B<DenyUsers> B<AllowUsers>

See PATTERNS in ssh_config5 for more information on patterns. This keyword may
appear multiple times in B<sshd_config> with each instance appending to the
list.',
        'type' => 'list'
      },
      'DisableForwarding',
      {
        'description' => 'Disables all forwarding features, including X11, ssh-agent1, TCP and
StreamLocal. This option overrides all other forwarding-related options and may
simplify restricted configurations.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ExposeAuthInfo',
      {
        'description' => 'Writes a temporary file containing a list of authentication methods and public
credentials (e.g. keys) used to authenticate the user. The location of the file
is exposed to the user session through the B<SSH_USER_AUTH> environment
variable. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'ForceCommand',
      {
        'description' => 'Forces the execution of the command specified by B<ForceCommand> ignoring any
command supplied by the client and ~/.ssh/rc if present. The command is invoked
by using the user\'s login shell with the -c option. This applies to shell,
command, or subsystem execution. It is most useful inside a B<Match> block. The
command originally supplied by the client is available in the
B<SSH_ORIGINAL_COMMAND> environment variable. Specifying a command of
B<internal-sftp> will force the use of an in-process SFTP server that requires
no support files when used with B<ChrootDirectory> The default is B<none>',
        'type' => 'leaf',
        'upstream_default' => 'none',
        'value_type' => 'uniline'
      },
      'GatewayPorts',
      {
        'choice' => [
          'clientspecified',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether remote hosts are allowed to connect to ports forwarded for
the client. By default, L<sshd(8)> binds remote port forwardings to the
loopback address. This prevents other remote hosts from connecting to forwarded
ports. B<GatewayPorts> can be used to specify that sshd should allow remote
port forwardings to bind to non-loopback addresses, thus allowing other hosts
to connect. The argument may be B<no> to force remote port forwardings to be
available to the local host only, B<yes> to force remote port forwardings to
bind to the wildcard address, or B<clientspecified> to allow the client to
select the address to which the forwarding is bound. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'GSSAPIAuthentication',
      {
        'description' => 'Specifies whether user authentication based on GSSAPI is allowed. The default
is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'HostbasedAcceptedAlgorithms',
      {
        'description' => 'Specifies the signature algorithms that will be accepted for hostbased
authentication as a list of comma-separated patterns. Alternately if the
specified list begins with a \'+\' character, then the specified signature
algorithms will be appended to the default set instead of replacing them. If
the specified list begins with a \'-\' character, then the specified signature
algorithms (including wildcards) will be removed from the default set instead
of replacing them. If the specified list begins with a \'^\' character, then the
specified signature algorithms will be placed at the head of the default set.
The default for this option is: ssh-ed25519-cert-v01@openssh.com,
ecdsa-sha2-nistp256-cert-v01@openssh.com,
ecdsa-sha2-nistp384-cert-v01@openssh.com,
ecdsa-sha2-nistp521-cert-v01@openssh.com, sk-ssh-ed25519-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com, rsa-sha2-512-cert-v01@openssh.com,
rsa-sha2-256-cert-v01@openssh.com, ssh-ed25519, ecdsa-sha2-nistp256,
ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ssh-ed25519@openssh.com,
sk-ecdsa-sha2-nistp256@openssh.com, rsa-sha2-512, rsa-sha2-256

The list of available signature algorithms may also be obtained using Qq ssh -Q
HostbasedAcceptedAlgorithms . This was formerly named
HostbasedAcceptedKeyTypes.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostbasedAuthentication',
      {
        'description' => 'Specifies whether rhosts or /etc/hosts.equiv authentication together with
successful public key client host authentication is allowed (host-based
authentication). The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'HostbasedUsesNameFromPacketOnly',
      {
        'description' => 'Specifies whether or not the server will attempt to perform a reverse name
lookup when matching the name in the ~/.shosts ~/.rhosts and /etc/hosts.equiv
files during B<HostbasedAuthentication> A setting of B<yes> means that
L<sshd(8)> uses the name supplied by the client rather than attempting to
resolve the name from the TCP connection itself. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'IgnoreRhosts',
      {
        'description' => 'Specifies whether to ignore per-user .rhosts and .shosts files during
B<HostbasedAuthentication> The system-wide /etc/hosts.equiv and
/etc/ssh/shosts.equiv are still used regardless of this setting.

Accepted values are B<yes> (the default) to ignore all per-user files,
B<shosts-only> to allow the use of .shosts but to ignore .rhosts or B<no> to
allow both .shosts and rhosts',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'Include',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Include the specified configuration file(s). Multiple pathnames may be
specified and each pathname may contain L<glob(7)> wildcards that will be
expanded and processed in lexical order. Files without absolute paths are
assumed to be in /etc/ssh An B<Include> directive may appear inside a B<Match>
block to perform conditional inclusion.',
        'type' => 'list'
      },
      'IPQoS',
      {
        'assert' => {
          '1_or_2' => {
            'code' => 'return 1 unless defined $_;
my @v = (/(\\w+)/g);
return  (@v < 3) ? 1 : 0;
',
            'msg' => 'value must not have more than 2 fields.'
          },
          'accepted_values' => {
            'code' => 'return 1 unless defined $_;
my @v = (/(\\S+)/g);
my @good = grep {/^(af[1-4][1-3]|cs[0-7]|ef|lowdelay|throughput|reliability|\\d+)/} @v ;
return @good == @v ? 1 : 0;
',
            'msg' => 'Unexpected value "$_". Expected 1 or 2 occurences of: "af11", "af12", "af13", "af21", "af22",
"af23", "af31", "af32", "af33", "af41", "af42", "af43", "cs0", "cs1",
"cs2", "cs3", "cs4", "cs5", "cs6", "cs7", "ef", "lowdelay",
"throughput", "reliability", or numeric value.
'
          }
        },
        'description' => 'Specifies the IPv4 type-of-service or DSCP class for the connection. Accepted
values are B<af11> B<af12> B<af13> B<af21> B<af22> B<af23> B<af31> B<af32>
B<af33> B<af41> B<af42> B<af43> B<cs0> B<cs1> B<cs2> B<cs3> B<cs4> B<cs5>
B<cs6> B<cs7> B<ef> B<le> B<lowdelay> B<throughput> B<reliability> a numeric
value, or B<none> to use the operating system default. This option may take one
or two arguments, separated by whitespace. If one argument is specified, it is
used as the packet class unconditionally. If two values are specified, the
first is automatically selected for interactive sessions and the second for
non-interactive sessions. The default is B<lowdelay> for interactive sessions
and B<throughput> for non-interactive sessions.',
        'type' => 'leaf',
        'upstream_default' => 'af21 cs1',
        'value_type' => 'uniline'
      },
      'KbdInteractiveAuthentication',
      {
        'description' => 'Specifies whether to allow keyboard-interactive authentication. The default is
B<yes> The argument to this keyword must be B<yes> or B<no>
B<ChallengeResponseAuthentication> is a deprecated alias for this.',
        'migrate_from' => {
          'formula' => '$old',
          'variables' => {
            'old' => '- ChallengeResponseAuthentication'
          }
        },
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KerberosAuthentication',
      {
        'description' => 'Specifies whether the password provided by the user for
B<PasswordAuthentication> will be validated through the Kerberos KDC. To use
this option, the server needs a Kerberos servtab which allows the verification
of the KDC\'s identity. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'LogLevel',
      {
        'choice' => [
          'DEBUG',
          'DEBUG1',
          'DEBUG2',
          'DEBUG3',
          'ERROR',
          'FATAL',
          'INFO',
          'QUIET',
          'VERBOSE'
        ],
        'description' => 'Gives the verbosity level that is used when logging messages from L<sshd(8)>.
The possible values are: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1,
DEBUG2, and DEBUG3. The default is INFO. DEBUG and DEBUG1 are equivalent.
DEBUG2 and DEBUG3 each specify higher levels of debugging output. Logging with
a DEBUG level violates the privacy of users and is not recommended.',
        'type' => 'leaf',
        'upstream_default' => 'INFO',
        'value_type' => 'enum'
      },
      'MaxAuthTries',
      {
        'description' => 'Specifies the maximum number of authentication attempts permitted per
connection. Once the number of failures reaches half this value, additional
failures are logged. The default is 6.',
        'type' => 'leaf',
        'upstream_default' => '6',
        'value_type' => 'integer'
      },
      'MaxSessions',
      {
        'description' => 'Specifies the maximum number of open shell, login or subsystem (e.g. sftp)
sessions permitted per network connection. Multiple sessions may be established
by clients that support connection multiplexing. Setting B<MaxSessions> to 1
will effectively disable session multiplexing, whereas setting it to 0 will
prevent all shell, login and subsystem sessions while still permitting
forwarding. The default is 10.',
        'type' => 'leaf',
        'upstream_default' => '10',
        'value_type' => 'integer'
      },
      'PAMServiceName',
      {
        'description' => 'Specifies the service name used for Pluggable Authentication Modules (PAM)
authentication, authorisation and session controls when B<UsePAM> is enabled.
The default is B<sshd>',
        'level' => 'hidden',
        'type' => 'leaf',
        'value_type' => 'uniline',
        'warp' => {
          'follow' => {
            'use_pam' => '- UsePAM'
          },
          'rules' => [
            '$use_pam',
            {
              'level' => 'normal'
            }
          ]
        }
      },
      'PasswordAuthentication',
      {
        'description' => 'Specifies whether password authentication is allowed. The default is B<sshd>',
        'type' => 'leaf',
        'upstream_default' => 'sshd',
        'value_type' => 'uniline'
      },
      'PermitEmptyPasswords',
      {
        'description' => 'When password authentication is allowed, it specifies whether the server allows
login to accounts with empty password strings. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PermitListen',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies the addresses/ports on which a remote TCP port forwarding may listen.
The listen specification must be one of the following forms:

B<PermitListen> I<port> B<PermitListen> I<host : port>

Multiple permissions may be specified by separating them with whitespace. An
argument of B<any> can be used to remove all restrictions and permit any listen
requests. An argument of B<none> can be used to prohibit all listen requests.
The host name may contain wildcards as described in the PATTERNS section in
ssh_config5. The wildcard \'*\' can also be used in place of a port number to
allow all ports. By default all port forwarding listen requests are permitted.
Note that the B<GatewayPorts> option may further restrict which addresses may
be listened on. Note also that L<ssh(1)> will request a listen host of
\'\'localhost\'\' if no listen host was specifically requested, and this name is
treated differently to explicit localhost addresses of \'\'127.0.0.1\'\' and
\'\'::1\'\'',
        'type' => 'list'
      },
      'PermitOpen',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies the destinations to which TCP port forwarding is permitted. The
forwarding specification must be one of the following forms:

B<PermitOpen> I<host : port> B<PermitOpen> I<IPv4_addr : port> B<PermitOpen>
I<[ IPv6_addr ] : port>

Multiple forwards may be specified by separating them with whitespace. An
argument of B<any> can be used to remove all restrictions and permit any
forwarding requests. An argument of B<none> can be used to prohibit all
forwarding requests. The wildcard \'*\' can be used for host or port to allow all
hosts or ports respectively. Otherwise, no pattern matching or address lookups
are performed on supplied names. By default all port forwarding requests are
permitted.',
        'type' => 'list'
      },
      'PermitRootLogin',
      {
        'choice' => [
          'forced-commands-only',
          'no',
          'prohibit-password',
          'yes'
        ],
        'description' => 'Specifies whether root can log in using L<ssh(1)>. The argument must be B<yes>
B<prohibit-password> B<forced-commands-only> or B<no> The default is
B<prohibit-password>

If this option is set to B<prohibit-password> (or its deprecated alias,
B<without-password )> password and keyboard-interactive authentication are
disabled for root.

If this option is set to B<forced-commands-only> root login with public key
authentication will be allowed, but only if the I<command> option has been
specified (which may be useful for taking remote backups even if root login is
normally not allowed). All other authentication methods are disabled for root.

If this option is set to B<no> root is not allowed to log in.',
        'type' => 'leaf',
        'value_type' => 'enum'
      },
      'PermitTTY',
      {
        'description' => 'Specifies whether L<pty(4)> allocation is permitted. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PermitTunnel',
      {
        'choice' => [
          'ethernet',
          'no',
          'point-to-point',
          'yes'
        ],
        'description' => 'Specifies whether L<tun(4)> device forwarding is allowed. The argument must be
B<yes> B<point-to-point> (layer 3), B<ethernet> (layer 2), or B<no> Specifying
B<yes> permits both B<point-to-point> and B<ethernet> The default is B<no>

Independent of this setting, the permissions of the selected L<tun(4)> device
must allow access to the user.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'PermitUserRC',
      {
        'description' => 'Specifies whether any ~/.ssh/rc file is executed. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PubkeyAcceptedAlgorithms',
      {
        'description' => 'Specifies the signature algorithms that will be accepted for public key
authentication as a list of comma-separated patterns. Alternately if the
specified list begins with a \'+\' character, then the specified algorithms will
be appended to the default set instead of replacing them. If the specified list
begins with a \'-\' character, then the specified algorithms (including
wildcards) will be removed from the default set instead of replacing them. If
the specified list begins with a \'^\' character, then the specified algorithms
will be placed at the head of the default set. The default for this option is:
ssh-ed25519-cert-v01@openssh.com, ecdsa-sha2-nistp256-cert-v01@openssh.com,
ecdsa-sha2-nistp384-cert-v01@openssh.com,
ecdsa-sha2-nistp521-cert-v01@openssh.com, sk-ssh-ed25519-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com, rsa-sha2-512-cert-v01@openssh.com,
rsa-sha2-256-cert-v01@openssh.com, ssh-ed25519, ecdsa-sha2-nistp256,
ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ssh-ed25519@openssh.com,
sk-ecdsa-sha2-nistp256@openssh.com, rsa-sha2-512, rsa-sha2-256

The list of available signature algorithms may also be obtained using Qq ssh -Q
PubkeyAcceptedAlgorithms .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PubkeyAuthOptions',
      {
        'choice' => [
          'none',
          'touch-required',
          'verify-required'
        ],
        'description' => 'Sets one or more public key authentication options. The supported keywords are:
B<none> (the default; indicating no additional options are enabled),
B<touch-required> and B<verify-required>

The B<touch-required> option causes public key authentication using a FIDO
authenticator algorithm (i.e. B<ecdsa-sk> or B<ed25519-sk> to always require
the signature to attest that a physically present user explicitly confirmed the
authentication (usually by touching the authenticator). By default, L<sshd(8)>
requires user presence unless overridden with an authorized_keys option. The
B<touch-required> flag disables this override.

The B<verify-required> option requires a FIDO key signature attest that the
user was verified, e.g. via a PIN.

Neither the B<touch-required> or B<verify-required> options have any effect for
other, non-FIDO, public key types.',
        'type' => 'leaf',
        'value_type' => 'enum'
      },
      'PubkeyAuthentication',
      {
        'description' => 'Specifies whether public key authentication is allowed. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'RekeyLimit',
      {
        'description' => 'Specifies the maximum amount of data that may be transmitted or received before
the session key is renegotiated, optionally followed by a maximum amount of
time that may pass before the session key is renegotiated. The first argument
is specified in bytes and may have a suffix of \'K\' \'M\' or \'G\' to indicate
Kilobytes, Megabytes, or Gigabytes, respectively. The default is between \'1G\'
and \'4G\' depending on the cipher. The optional second value is specified in
seconds and may use any of the units documented in the I<TIME FORMATS> section.
The default value for B<RekeyLimit> is B<default none> which means that
rekeying is performed after the cipher\'s default amount of data has been sent
or received and no time based rekeying is done.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RevokedKeys',
      {
        'description' => 'Specifies revoked public keys file, or B<none> to not use one. Keys listed in
this file will be refused for public key authentication. Note that if this file
is not readable, then public key authentication will be refused for all users.
Keys may be specified as a text file, listing one public key per line, or as an
OpenSSH Key Revocation List (KRL) as generated by ssh-keygen1. For more
information on KRLs, see the KEY REVOCATION LISTS section in ssh-keygen1.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'SetEnv',
      {
        'description' => 'Specifies one or more environment variables to set in child sessions started by
L<sshd(8)> as \'\'NAME=VALUE\'\' The environment value may be quoted (e.g. if it
contains whitespace characters). Environment variables set by B<SetEnv>
override the default environment and any variables specified by the user via
B<AcceptEnv> or B<PermitUserEnvironment>',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'StreamLocalBindMask',
      {
        'description' => 'Sets the octal file creation mode mask (umask) used when creating a Unix-domain
socket file for local or remote port forwarding. This option is only used for
port forwarding to a Unix-domain socket file.

The default value is 0177, which creates a Unix-domain socket file that is
readable and writable only by the owner. Note that not all operating systems
honor the file mode on Unix-domain socket files.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'StreamLocalBindUnlink',
      {
        'description' => 'Specifies whether to remove an existing Unix-domain socket file for local or
remote port forwarding before creating a new one. If the socket file already
exists and B<StreamLocalBindUnlink> is not enabled, B<sshd> will be unable to
forward the port to the Unix-domain socket file. This option is only used for
port forwarding to a Unix-domain socket file.

The argument must be B<yes> or B<no> The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'TrustedUserCAKeys',
      {
        'description' => 'Specifies a file containing public keys of certificate authorities that are
trusted to sign user certificates for authentication, or B<none> to not use
one. Keys are listed one per line; empty lines and comments starting with \'#\'
are allowed. If a certificate is presented for authentication and has its
signing CA key listed in this file, then it may be used for authentication for
any user listed in the certificate\'s principals list. Note that certificates
that lack a list of principals will not be permitted for authentication using
B<TrustedUserCAKeys> For more details on certificates, see the CERTIFICATES
section in ssh-keygen1.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'UnusedConnectionTimeout',
      {
        'description' => 'Specifies whether and how quickly L<sshd(8)> should close client connections
with no open channels. Open channels include active shell, command execution or
subsystem sessions, connected network, socket, agent or X11 forwardings.
Forwarding listeners, such as those from the L<ssh(1)> -B<R> flag, are not
considered as open channels and do not prevent the timeout. The timeout value
is specified in seconds or may use any of the units documented in the I<TIME
FORMATS> section.

Note that this timeout starts when the client connection completes user
authentication but before the client has an opportunity to open any channels.
Caution should be used when using short timeout values, as they may not provide
sufficient time for the client to request and open its channels before
terminating the connection.

The default B<none> is to never expire connections for having no open channels.
This option may be useful in conjunction with B<ChannelTimeout>',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'X11DisplayOffset',
      {
        'description' => 'Specifies the first display number available for L<sshd(8)>Ns\'s X11 forwarding.
This prevents sshd from interfering with real X11 servers. The default is 10.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'X11Forwarding',
      {
        'description' => 'Specifies whether X11 forwarding is permitted. The argument must be B<yes> or
B<no> The default is B<no>

When X11 forwarding is enabled, there may be additional exposure to the server
and to client displays if the L<sshd(8)> proxy display is configured to listen
on the wildcard address (see B<X11UseLocalhost )> though this is not the
default. Additionally, the authentication spoofing and authentication data
verification and substitution occur on the client side. The security risk of
using X11 forwarding is that the client\'s X11 display server may be exposed to
attack when the SSH client requests forwarding (see the warnings for
B<ForwardX11> in ssh_config5). A system administrator may have a stance in
which they want to protect clients that may expose themselves to attack by
unwittingly requesting X11 forwarding, which can warrant a B<no> setting.

Note that disabling X11 forwarding does not prevent users from forwarding X11
traffic, as users can always install their own forwarders.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'X11UseLocalhost',
      {
        'description' => 'Specifies whether L<sshd(8)> should bind the X11 forwarding server to the
loopback address or to the wildcard address. By default, sshd binds the
forwarding server to the loopback address and sets the hostname part of the
B<DISPLAY> environment variable to B<localhost> This prevents remote hosts from
connecting to the proxy display. However, some older X11 clients may not
function with this configuration. B<X11UseLocalhost> may be set to B<no> to
specify that the forwarding server should be bound to the wildcard address. The
argument must be B<yes> or B<no> The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'AuthorizedKeysFile2',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'This parameter is now ignored by Ssh',
        'status' => 'deprecated',
        'type' => 'list'
      },
      'ChallengeResponseAuthentication',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'boolean'
      },
      'KeyRegenerationInterval',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Protocol',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RDomain',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RSAAuthentication',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RhostsRSAAuthentication',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'UsePrivilegeSeparation',
      {
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      }
    ],
    'generated_by' => 'parse-man.pl from sshd_system  9.8p1 doc',
    'license' => 'LGPL2',
    'name' => 'Sshd::MatchElement'
  }
]
;

