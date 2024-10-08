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
      'AddKeysToAgent',
      {
        'choice' => [
          'ask',
          'confirm',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether keys should be automatically added to a running ssh-agent1.
If this option is set to B<yes> and a key is loaded from a file, the key and
its passphrase are added to the agent with the default lifetime, as if by
ssh-add1. If this option is set to B<ask> L<ssh(1)> will require confirmation
using the B<SSH_ASKPASS> program before adding a key (see ssh-add1 for
details). If this option is set to B<confirm> each use of the key must be
confirmed, as if the -B<c> option was specified to ssh-add1. If this option is
set to B<no> no keys are added to the agent. Alternately, this option may be
specified as a time interval using the format described in the I<TIME FORMATS>
section of sshd_config5 to specify the key\'s lifetime in ssh-agent1, after
which it will automatically be removed. The argument must be B<no> (the
default), B<yes> B<confirm> (optionally followed by a time interval), B<ask> or
a time interval.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'AddressFamily',
      {
        'choice' => [
          'any',
          'inet',
          'inet6'
        ],
        'description' => 'Specifies which address family to use when connecting. Valid arguments are
B<any> (the default), B<inet> (use IPv4 only), or B<inet6> (use IPv6 only).',
        'type' => 'leaf',
        'upstream_default' => 'any',
        'value_type' => 'enum'
      },
      'BatchMode',
      {
        'description' => 'If set to B<yes> user interaction such as password prompts and host key
confirmation requests will be disabled. In addition, the B<ServerAliveInterval>
option will be set to 300 seconds by default (Debian-specific). This option is
useful in scripts and other batch jobs where no user is present to interact
with L<ssh(1)>, and where it is desirable to detect a broken network swiftly.
The argument must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'BindAddress',
      {
        'description' => 'Use the specified address on the local machine as the source address of the
connection. Only useful on systems with more than one address.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'BindInterface',
      {
        'description' => 'Use the address of the specified interface on the local machine as the source
address of the connection.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'CanonicalDomains',
      {
        'description' => 'When B<CanonicalizeHostname> is enabled, this option specifies the list of
domain suffixes in which to search for the specified destination host.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'CanonicalizeFallbackLocal',
      {
        'description' => 'Specifies whether to fail with an error when hostname canonicalization fails.
The default, B<yes> will attempt to look up the unqualified hostname using the
system resolver\'s search rules. A value of B<no> will cause L<ssh(1)> to fail
instantly if B<CanonicalizeHostname> is enabled and the target hostname cannot
be found in any of the domains specified by B<CanonicalDomains>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'CanonicalizeHostname',
      {
        'choice' => [
          'always',
          'no',
          'none',
          'yes'
        ],
        'description' => 'Controls whether explicit hostname canonicalization is performed. The default,
B<no> is not to perform any name rewriting and let the system resolver handle
all hostname lookups. If set to B<yes> then, for connections that do not use a
B<ProxyCommand> or B<ProxyJump> L<ssh(1)> will attempt to canonicalize the
hostname specified on the command line using the B<CanonicalDomains> suffixes
and B<CanonicalizePermittedCNAMEs> rules. If B<CanonicalizeHostname> is set to
B<always> then canonicalization is applied to proxied connections too.

If this option is enabled, then the configuration files are processed again
using the new target name to pick up any new configuration in matching B<Host>
and B<Match> stanzas. A value of B<none> disables the use of a B<ProxyJump>
host.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'CanonicalizeMaxDots',
      {
        'description' => 'Specifies the maximum number of dot characters in a hostname before
canonicalization is disabled. The default, 1, allows a single dot (i.e.
hostname.subdomain).',
        'type' => 'leaf',
        'upstream_default' => '1',
        'value_type' => 'integer'
      },
      'CanonicalizePermittedCNAMEs',
      {
        'description' => 'Specifies rules to determine whether CNAMEs should be followed when

canonicalizing hostnames. The rules consist of one or more arguments of
I<source_domain_list : > B<> I<target_domain_list> where I<source_domain_list>
is a pattern-list of domains that may follow CNAMEs in canonicalization, and
I<target_domain_list> is a pattern-list of domains that they may resolve to.

For example, Qq *.a.example.com:*.b.example.com,*.c.example.com will allow
hostnames matching Qq *.a.example.com to be canonicalized to names in the Qq
*.b.example.com or Qq *.c.example.com domains.

A single argument of Qq none causes no CNAMEs to be considered for
canonicalization. This is the default behaviour.',
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

L<ssh(1)> will not accept host certificates signed using algorithms other than
those specified.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'CertificateFile',
      {
        'description' => 'Specifies a file from which the user\'s certificate is read. A corresponding
private key must be provided separately in order to use this certificate either
from an B<IdentityFile> directive or -B<i> flag to L<ssh(1)>, via ssh-agent1,
or via a B<PKCS11Provider> or B<SecurityKeyProvider>

Arguments to B<CertificateFile> may use the tilde syntax to refer to a user\'s
home directory, the tokens described in the I<TOKENS> section and environment
variables as described in the I<ENVIRONMENT VARIABLES> section.

It is possible to have multiple certificate files specified in configuration
files; these certificates will be tried in sequence. Multiple
B<CertificateFile> directives will add to the list of certificates used for
authentication.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ChannelTimeout',
      {
        'description' => 'Specifies whether and how quickly L<ssh(1)> should close inactive channels.
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
      'CheckHostIP',
      {
        'description' => 'If set to B<yes> L<ssh(1)> will additionally check the host IP address in the
known_hosts file. This allows it to detect if a host key changed due to DNS
spoofing and will add addresses of destination hosts to ~/.ssh/known_hosts in
the process, regardless of the setting of B<StrictHostKeyChecking> If the
option is set to B<no> (the default), the check will not be executed.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'Ciphers',
      {
        'description' => 'Specifies the ciphers allowed and their order of preference. Multiple ciphers
must be comma-separated. If the specified list begins with a \'+\' character,
then the specified ciphers will be appended to the default set instead of
replacing them. If the specified list begins with a \'-\' character, then the
specified ciphers (including wildcards) will be removed from the default set
instead of replacing them. If the specified list begins with a \'^\' character,
then the specified ciphers will be placed at the head of the default set.

The supported ciphers are: 3des-cbc aes128-cbc aes192-cbc aes256-cbc aes128-ctr
aes192-ctr aes256-ctr
aes128-gcm@openssh.comaes256-gcm@openssh.comchacha20-poly1305@openssh.com

The default is: chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr,
aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com

The list of available ciphers may also be obtained using Qq ssh -Q cipher .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ClearAllForwardings',
      {
        'description' => 'Specifies that all local, remote, and dynamic port forwardings specified in the
configuration files or on the command line be cleared. This option is primarily
useful when used from the L<ssh(1)> command line to clear port forwardings set
in configuration files, and is automatically set by L<scp(1)> and L<sftp(1)>.
The argument must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'Compression',
      {
        'description' => 'Specifies whether to use compression. The argument must be B<yes> or B<no> (the
default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'ConnectionAttempts',
      {
        'description' => 'Specifies the number of tries (one per second) to make before exiting. The
argument must be an integer. This may be useful in scripts if the connection
sometimes fails. The default is 1.',
        'type' => 'leaf',
        'upstream_default' => '1',
        'value_type' => 'integer'
      },
      'ConnectTimeout',
      {
        'description' => 'Specifies the timeout (in seconds) used when connecting to the SSH server,
instead of using the default system TCP timeout. This timeout is applied both
to establishing the connection and to performing the initial SSH protocol
handshake and key exchange.',
        'type' => 'leaf',
        'value_type' => 'integer'
      },
      'ControlMaster',
      {
        'choice' => [
          'ask',
          'auto',
          'autoask',
          'no',
          'yes'
        ],
        'description' => 'Enables the sharing of multiple sessions over a single network connection. When
set to B<yes> L<ssh(1)> will listen for connections on a control socket
specified using the B<ControlPath> argument. Additional sessions can connect to
this socket using the same B<ControlPath> with B<ControlMaster> set to B<no>
(the default). These sessions will try to reuse the master instance\'s network
connection rather than initiating new ones, but will fall back to connecting
normally if the control socket does not exist, or is not listening.

Setting this to B<ask> will cause L<ssh(1)> to listen for control connections,
but require confirmation using ssh-askpass1. If the B<ControlPath> cannot be
opened, L<ssh(1)> will continue without connecting to a master instance.

X11 and ssh-agent1 forwarding is supported over these multiplexed connections,
however the display and agent forwarded will be the one belonging to the master
connection i.e. it is not possible to forward multiple displays or agents.

Two additional options allow for opportunistic multiplexing: try to use a
master connection but fall back to creating a new one if one does not already
exist. These options are: B<auto> and B<autoask> The latter requires
confirmation like the B<ask> option.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'ControlPath',
      {
        'description' => 'Specify the path to the control socket used for connection sharing as described
in the B<ControlMaster> section above or the string B<none> to disable
connection sharing. Arguments to B<ControlPath> may use the tilde syntax to
refer to a user\'s home directory, the tokens described in the I<TOKENS> section
and environment variables as described in the I<ENVIRONMENT VARIABLES> section.
It is recommended that any B<ControlPath> used for opportunistic connection
sharing include at least %h, %p, and %r (or alternatively %C) and be placed in
a directory that is not writable by other users. This ensures that shared
connections are uniquely identified.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ControlPersist',
      {
        'description' => 'When used in conjunction with B<ControlMaster> specifies that the master
connection should remain open in the background (waiting for future client
connections) after the initial client connection has been closed. If set to
B<no> (the default), then the master connection will not be placed into the
background, and will close as soon as the initial client connection is closed.
If set to B<yes> or 0, then the master connection will remain in the background
indefinitely (until killed or closed via a mechanism such as the Qq ssh -O exit
) . If set to a time in seconds, or a time in any of the formats documented in
sshd_config5, then the backgrounded master connection will automatically
terminate after it has remained idle (with no client connections) for the
specified time.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'DynamicForward',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies that a TCP port on the local machine be forwarded over the secure
channel, and the application protocol is then used to determine where to
connect to from the remote machine.

The argument must be [I<bind_address : port> ] IPv6 addresses can be specified
by enclosing addresses in square brackets. By default, the local port is bound
in accordance with the B<GatewayPorts> setting. However, an explicit
I<bind_address> may be used to bind the connection to a specific address. The
I<bind_address> of B<localhost> indicates that the listening port be bound for
local use only, while an empty address or \'*\' indicates that the port should be
available from all interfaces.

Currently the SOCKS4 and SOCKS5 protocols are supported, and L<ssh(1)> will act
as a SOCKS server. Multiple forwardings may be specified, and additional
forwardings can be given on the command line. Only the superuser can forward
privileged ports.',
        'type' => 'list'
      },
      'EnableEscapeCommandline',
      {
        'description' => 'Enables the command line option in the B<EscapeChar> menu for interactive
sessions (default \'~C\' ) . By default, the command line is disabled.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'EnableSSHKeysign',
      {
        'description' => 'Setting this option to B<yes> in the global client configuration file
/etc/ssh/ssh_config enables the use of the helper program ssh-keysign8 during
B<HostbasedAuthentication> The argument must be B<yes> or B<no> (the default).
This option should be placed in the non-hostspecific section. See ssh-keysign8
for more information.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'EscapeChar',
      {
        'description' => 'Sets the escape character (default: \'~\' ) . The escape character can also be
set on the command line. The argument should be a single character, \'^\'
followed by a letter, or B<none> to disable the escape character entirely
(making the connection transparent for binary data).',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ExitOnForwardFailure',
      {
        'description' => 'Specifies whether L<ssh(1)> should terminate the connection if it cannot set up
all requested dynamic, tunnel, local, and remote port forwardings, (e.g. if
either end is unable to bind and listen on a specified port). Note that
B<ExitOnForwardFailure> does not apply to connections made over port
forwardings and will not, for example, cause L<ssh(1)> to exit if TCP
connections to the ultimate forwarding destination fail. The argument must be
B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'FingerprintHash',
      {
        'choice' => [
          'md5',
          'sha256'
        ],
        'description' => 'Specifies the hash algorithm used when displaying key fingerprints. Valid
options are: B<md5> and B<sha256> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'sha256',
        'value_type' => 'enum'
      },
      'ForkAfterAuthentication',
      {
        'description' => 'Requests B<ssh> to go to background just before command execution. This is
useful if B<ssh> is going to ask for passwords or passphrases, but the user
wants it in the background. This implies the B<StdinNull> configuration option
being set to \'\'yes\'\' The recommended way to start X11 programs at a remote site
is with something like B<ssh -f host xterm> which is the same as B<ssh host
xterm> if the B<ForkAfterAuthentication> configuration option is set to \'\'yes\'\'

If the B<ExitOnForwardFailure> configuration option is set to \'\'yes\'\' then a
client started with the B<ForkAfterAuthentication> configuration option being
set to \'\'yes\'\' will wait for all remote port forwards to be successfully
established before placing itself in the background. The argument to this
keyword must be B<yes> (same as the -B<f> option) or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'ForwardAgent',
      {
        'description' => 'Specifies whether the connection to the authentication agent (if any) will be
forwarded to the remote machine. The argument may be B<yes> B<no> (the
default), an explicit path to an agent socket or the name of an environment
variable (beginning with \'$\' in which to find the path.

Agent forwarding should be enabled with caution. Users with the ability to
bypass file permissions on the remote host (for the agent\'s Unix-domain socket)
can access the local agent through the forwarded connection. An attacker cannot
obtain key material from the agent, however they can perform operations on the
keys that enable them to authenticate using the identities loaded into the
agent.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'ForwardX11',
      {
        'description' => 'Specifies whether X11 connections will be automatically redirected over the
secure channel and B<DISPLAY> set. The argument must be B<yes> or B<no> (the
default).

X11 forwarding should be enabled with caution. Users with the ability to bypass
file permissions on the remote host (for the user\'s X11 authorization database)
can access the local X11 display through the forwarded connection. An attacker
may then be able to perform activities such as keystroke monitoring if the
B<ForwardX11Trusted> option is also enabled.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'ForwardX11Timeout',
      {
        'description' => 'Specify a timeout for untrusted X11 forwarding using the format described in
the I<TIME FORMATS> section of sshd_config5. X11 connections received by
L<ssh(1)> after this time will be refused. Setting B<ForwardX11Timeout> to zero
will disable the timeout and permit X11 forwarding for the life of the
connection. The default is to disable untrusted X11 forwarding after twenty
minutes has elapsed.',
        'type' => 'leaf',
        'value_type' => 'integer'
      },
      'ForwardX11Trusted',
      {
        'description' => 'If this option is set to B<yes> (the Debian-specific default), remote X11
clients will have full access to the original X11 display.

If this option is set to B<no> (the upstream default), remote X11 clients will
be considered untrusted and prevented from stealing or tampering with data
belonging to trusted X11 clients. Furthermore, the L<xauth(1)> token used for
the session will be set to expire after 20 minutes. Remote clients will be
refused access after this time.

See the X11 SECURITY extension specification for full details on the
restrictions imposed on untrusted clients.',
        'type' => 'leaf',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GatewayPorts',
      {
        'description' => 'Specifies whether remote hosts are allowed to connect to local forwarded ports.
By default, L<ssh(1)> binds local port forwardings to the loopback address.
This prevents other remote hosts from connecting to forwarded ports.
B<GatewayPorts> can be used to specify that ssh should bind local port
forwardings to the wildcard address, thus allowing remote hosts to connect to
forwarded ports. The argument must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GlobalKnownHostsFile',
      {
        'default' => '/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2',
        'description' => 'Specifies one or more files to use for the global host key database, separated
by whitespace. The default is /etc/ssh/ssh_known_hosts
/etc/ssh/ssh_known_hosts2',
        'type' => 'leaf',
        'value_type' => 'uniline'
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
      'GSSAPIClientIdentity',
      {
        'description' => 'If set, specifies the GSSAPI client identity that ssh should use when
connecting to the server. The default is unset, which means that the default
identity will be used.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'GSSAPIDelegateCredentials',
      {
        'description' => 'Forward (delegate) credentials to the server. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GSSAPIKeyExchange',
      {
        'description' => 'Specifies whether key exchange based on GSSAPI may be used. When using GSSAPI
key exchange the server need not have a host key. The default is \'\'no\'\'',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'GSSAPIRenewalForcesRekey',
      {
        'description' => 'If set to \'\'yes\'\' then renewal of the client\'s GSSAPI credentials will force
the rekeying of the ssh connection. With a compatible server, this will
delegate the renewed credentials to a session on the server.

Checks are made to ensure that credentials are only propagated when the new
credentials match the old ones on the originating client and where the
receiving server still has the old set in its cache.

The default is \'\'no\'\'

For this to work B<GSSAPIKeyExchange> needs to be enabled in the server and
also used by the client.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'GSSAPIServerIdentity',
      {
        'description' => 'If set, specifies the GSSAPI server identity that ssh should expect when
connecting to the server. The default is unset, which means that the expected
GSSAPI server identity will be determined from the target hostname.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'GSSAPITrustDns',
      {
        'description' => 'Set to \'\'yes\'\' to indicate that the DNS is trusted to securely canonicalize the
name of the host being connected to. If \'\'no\'\' the hostname entered on the
command line will be passed untouched to the GSSAPI library. The default is
\'\'no\'\'',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'GSSAPIKexAlgorithms',
      {
        'description' => 'The list of key exchange algorithms that are offered for GSSAPI key exchange.
Possible values are gss-gex-sha1-, gss-group1-sha1-, gss-group14-sha1-,
gss-group14-sha256-, gss-group16-sha512-, gss-nistp256-sha256-,
gss-curve25519-sha256-

The default is \'\'gss-group14-sha256-, gss-group16-sha512-,
gss-nistp256-sha256-, gss-curve25519-sha256-, gss-gex-sha1-,
gss-group14-sha1-\'\' This option only applies to connections using GSSAPI.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HashKnownHosts',
      {
        'description' => 'Indicates that L<ssh(1)> should hash host names and addresses when they are
added to ~/.ssh/known_hosts These hashed names may be used normally by
L<ssh(1)> and L<sshd(8)>, but they do not visually reveal identifying
information if the file\'s contents are disclosed. The default is B<no> Note
that existing names and addresses in known hosts files will not be converted
automatically, but may be manually hashed using ssh-keygen1. Use of this option
may break facilities such as tab-completion that rely on being able to read
unhashed host names from ~/.ssh/known_hosts',
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
        'description' => 'Specifies the signature algorithms that will be used for hostbased
authentication as a comma-separated list of patterns. Alternately if the
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

The -B<Q> option of L<ssh(1)> may be used to list supported signature
algorithms. This was formerly named HostbasedKeyTypes.',
        'migrate_from' => {
          'formula' => '$old',
          'variables' => {
            'old' => '- HostbasedKeyTypes'
          }
        },
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostbasedAuthentication',
      {
        'description' => 'Specifies whether to try rhosts based authentication with public key
authentication. The argument must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'HostKeyAlgorithms',
      {
        'description' => 'Specifies the host key signature algorithms that the client wants to use in
order of preference. Alternately if the specified list begins with a \'+\'
character, then the specified signature algorithms will be appended to the
default set instead of replacing them. If the specified list begins with a \'-\'
character, then the specified signature algorithms (including wildcards) will
be removed from the default set instead of replacing them. If the specified
list begins with a \'^\' character, then the specified signature algorithms will
be placed at the head of the default set. The default for this option is:
ssh-ed25519-cert-v01@openssh.com, ecdsa-sha2-nistp256-cert-v01@openssh.com,
ecdsa-sha2-nistp384-cert-v01@openssh.com,
ecdsa-sha2-nistp521-cert-v01@openssh.com, sk-ssh-ed25519-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com, rsa-sha2-512-cert-v01@openssh.com,
rsa-sha2-256-cert-v01@openssh.com, ssh-ed25519, ecdsa-sha2-nistp256,
ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ecdsa-sha2-nistp256@openssh.com,
sk-ssh-ed25519@openssh.com, rsa-sha2-512, rsa-sha2-256

If hostkeys are known for the destination host then this default is modified to
prefer their algorithms.

The list of available signature algorithms may also be obtained using Qq ssh -Q
HostKeyAlgorithms .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostKeyAlias',
      {
        'description' => 'Specifies an alias that should be used instead of the real host name when
looking up or saving the host key in the host key database files and when
validating host certificates. This option is useful for tunneling SSH
connections or for multiple servers running on a single host.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Hostname',
      {
        'description' => 'Specifies the real host name to log into. This can be used to specify nicknames
or abbreviations for hosts. Arguments to B<Hostname> accept the tokens
described in the I<TOKENS> section. Numeric IP addresses are also permitted
(both on the command line and in B<Hostname> specifications). The default is
the name given on the command line.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'IdentitiesOnly',
      {
        'description' => 'Specifies that L<ssh(1)> should only use the configured authentication identity
and certificate files (either the default files, or those explicitly configured
in the B<ssh_config> files or passed on the L<ssh(1)> command-line), even if
ssh-agent1 or a B<PKCS11Provider> or B<SecurityKeyProvider> offers more
identities. The argument to this keyword must be B<yes> or B<no> (the default).
This option is intended for situations where ssh-agent offers many different
identities.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'IdentityAgent',
      {
        'description' => 'Specifies the UNIX socket used to communicate with the authentication agent.

This option overrides the B<SSH_AUTH_SOCK> environment variable and can be used
to select a specific agent. Setting the socket name to B<none> disables the use
of an authentication agent. If the string Qq SSH_AUTH_SOCK is specified, the
location of the socket will be read from the B<SSH_AUTH_SOCK> environment
variable. Otherwise if the specified value begins with a \'$\' character, then it
will be treated as an environment variable containing the location of the
socket.

Arguments to B<IdentityAgent> may use the tilde syntax to refer to a user\'s
home directory, the tokens described in the I<TOKENS> section and environment
variables as described in the I<ENVIRONMENT VARIABLES> section.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'IdentityFile',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline',
          'warn_if_match' => {
            '\\.pub$' => {
              'fix' => 's/\\.pub$//;',
              'msg' => 'identity file must be the private key'
            }
          }
        },
        'description' => 'Specifies a file from which the user\'s ECDSA, authenticator-hosted ECDSA,
Ed25519, authenticator-hosted Ed25519 or RSA authentication identity is read.
You can also specify a public key file to use the corresponding private key
that is loaded in ssh-agent1 when the private key file is not present locally.
The default is ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_ecdsa_sk
~/.ssh/id_ed25519 and ~/.ssh/id_ed25519_sk Additionally, any identities
represented by the authentication agent will be used for authentication unless
B<IdentitiesOnly> is set. If no certificates have been explicitly specified by
B<CertificateFile> L<ssh(1)> will try to load certificate information from the
filename obtained by appending -cert.pub to the path of a specified
B<IdentityFile>

Arguments to B<IdentityFile> may use the tilde syntax to refer to a user\'s home
directory or the tokens described in the I<TOKENS> section. Alternately an
argument of B<none> may be used to indicate no identity files should be loaded.

It is possible to have multiple identity files specified in configuration
files; all these identities will be tried in sequence. Multiple B<IdentityFile>
directives will add to the list of identities tried (this behaviour differs
from that of other configuration directives).

B<IdentityFile> may be used in conjunction with B<IdentitiesOnly> to select
which identities in an agent are offered during authentication. B<IdentityFile>
may also be used in conjunction with B<CertificateFile> in order to provide any
certificate also needed for authentication with the identity.',
        'type' => 'list'
      },
      'IgnoreUnknown',
      {
        'description' => 'Specifies a pattern-list of unknown options to be ignored if they are
encountered in configuration parsing. This may be used to suppress errors if
B<ssh_config> contains options that are unrecognised by L<ssh(1)>. It is
recommended that B<IgnoreUnknown> be listed early in the configuration file as
it will not be applied to unknown options that appear before it.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Include',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Include the specified configuration file(s). Multiple pathnames may be
specified and each pathname may contain L<glob(7)> wildcards and, for user
configurations, shell-like \'~\' references to user home directories. Wildcards
will be expanded and processed in lexical order. Files without absolute paths
are assumed to be in ~/.ssh if included in a user configuration file or
/etc/ssh if included from the system configuration file. B<Include> directive
may appear inside a B<Match> or B<Host> block to perform conditional inclusion.',
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
        'description' => 'Specifies the IPv4 type-of-service or DSCP class for connections. Accepted
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
        'description' => 'Specifies whether to use keyboard-interactive authentication. The argument to
this keyword must be B<yes> (the default) or B<no>
B<ChallengeResponseAuthentication> is a deprecated alias for this.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KbdInteractiveDevices',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies the list of methods to use in keyboard-interactive authentication.
Multiple method names must be comma-separated. The default is to use the server
specified list. The methods available vary depending on what the server
supports. For an OpenSSH server, it may be zero or more of: B<bsdauth> and
B<pam>',
        'type' => 'list'
      },
      'KexAlgorithms',
      {
        'description' => 'Specifies the permitted KEX (Key Exchange) algorithms that will be used and
their preference order. The selected algorithm will the the first algorithm in
this list that the server also supports. Multiple algorithms must be
comma-separated.

If the specified list begins with a \'+\' character, then the specified
algorithms will be appended to the default set instead of replacing them. If
the specified list begins with a \'-\' character, then the specified algorithms
(including wildcards) will be removed from the default set instead of replacing
them. If the specified list begins with a \'^\' character, then the specified
algorithms will be placed at the head of the default set.

The default is: sntrup761x25519-sha512@openssh.com, curve25519-sha256,
curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384,
ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256,
diffie-hellman-group16-sha512, diffie-hellman-group18-sha512,
diffie-hellman-group14-sha256

The list of supported key exchange algorithms may also be obtained using Qq ssh
-Q kex .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'KnownHostsCommand',
      {
        'description' => 'Specifies a command to use to obtain a list of host keys, in addition to those
listed in B<UserKnownHostsFile> and B<GlobalKnownHostsFile> This command is
executed after the files have been read. It may write host key lines to
standard output in identical format to the usual files (described in the
I<VERIFYING HOST KEYS> section in L<ssh(1)>). Arguments to B<KnownHostsCommand>
accept the tokens described in the I<TOKENS> section. The command may be
invoked multiple times per connection: once when preparing the preference list
of host key algorithms to use, again to obtain the host key for the requested
host name and, if B<CheckHostIP> is enabled, one more time to obtain the host
key matching the server\'s address. If the command exits abnormally or returns a
non-zero exit status then the connection is terminated.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'LocalCommand',
      {
        'description' => 'Specifies a command to execute on the local machine after successfully
connecting to the server. The command string extends to the end of the line,
and is executed with the user\'s shell. Arguments to B<LocalCommand> accept the
tokens described in the I<TOKENS> section.

The command is run synchronously and does not have access to the session of the
L<ssh(1)> that spawned it. It should not be used for interactive commands.

This directive is ignored unless B<PermitLocalCommand> has been enabled.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'LocalForward',
      {
        'cargo' => {
          'config_class_name' => 'Ssh::PortForward',
          'type' => 'node'
        },
        'description' => 'Specifies that a TCP port on the local machine be forwarded over the secure
channel to the specified host and port from the remote machine. The first
argument specifies the listener and may be [I<bind_address : port> ] or a Unix
domain socket path. The second argument is the destination and may be I<host :
> B<> I<hostport> or a Unix domain socket path if the remote host supports it.

IPv6 addresses can be specified by enclosing addresses in square brackets.
Multiple forwardings may be specified, and additional forwardings can be given
on the command line. Only the superuser can forward privileged ports. By
default, the local port is bound in accordance with the B<GatewayPorts>
setting. However, an explicit I<bind_address> may be used to bind the
connection to a specific address. The I<bind_address> of B<localhost> indicates
that the listening port be bound for local use only, while an empty address or
\'*\' indicates that the port should be available from all interfaces. Unix
domain socket paths may use the tokens described in the I<TOKENS> section and
environment variables as described in the I<ENVIRONMENT VARIABLES> section.',
        'type' => 'list'
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
        'description' => 'Gives the verbosity level that is used when logging messages from L<ssh(1)>.
The possible values are: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1,
DEBUG2, and DEBUG3. The default is INFO. DEBUG and DEBUG1 are equivalent.
DEBUG2 and DEBUG3 each specify higher levels of verbose output.',
        'type' => 'leaf',
        'upstream_default' => 'INFO',
        'value_type' => 'enum'
      },
      'LogVerbose',
      {
        'description' => 'Specify one or more overrides to LogLevel. An override consists of a pattern
lists that matches the source file, function and line number to force detailed
logging for. For example, an override pattern of:
kex.c:*:1000,*:kex_exchange_identification():*, packet.c:*

would enable detailed logging for line 1000 of kex.c everything in the Fn
kex_exchange_identification function, and all code in the packet.c file. This
option is intended for debugging and no overrides are enabled by default.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'MACs',
      {
        'description' => 'Specifies the MAC (message authentication code) algorithms

in order of preference. The MAC algorithm is used for data integrity
protection. Multiple algorithms must be comma-separated. If the specified list
begins with a \'+\' character, then the specified algorithms will be appended to
the default set instead of replacing them. If the specified list begins with a
\'-\' character, then the specified algorithms (including wildcards) will be
removed from the default set instead of replacing them. If the specified list
begins with a \'^\' character, then the specified algorithms will be placed at
the head of the default set.

The algorithms that contain Qq -etm calculate the MAC after encryption
(encrypt-then-mac). These are considered safer and their use recommended.

The default is: umac-64-etm@openssh.com, umac-128-etm@openssh.com,
hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com,
hmac-sha1-etm@openssh.com, umac-64@openssh.com, umac-128@openssh.com,
hmac-sha2-256, hmac-sha2-512, hmac-sha1

The list of available MAC algorithms may also be obtained using Qq ssh -Q mac .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'NoHostAuthenticationForLocalhost',
      {
        'description' => 'Disable host authentication for localhost (loopback addresses). The argument to
this keyword must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'NumberOfPasswordPrompts',
      {
        'description' => 'Specifies the number of password prompts before giving up. The argument to this
keyword must be an integer. The default is 3.',
        'type' => 'leaf',
        'upstream_default' => '3',
        'value_type' => 'integer'
      },
      'ObscureKeystrokeTiming',
      {
        'description' => 'Specifies whether L<ssh(1)> should try to obscure inter-keystroke timings from
passive observers of network traffic. If enabled, then for interactive
sessions, L<ssh(1)> will send keystrokes at fixed intervals of a few tens of
milliseconds and will send fake keystroke packets for some time after typing
ceases. The argument to this keyword must be B<yes> B<no> or an interval
specifier of the form B<interval:milliseconds> (e.g. B<interval:80> for 80
milliseconds). The default is to obscure keystrokes using a 20ms packet
interval. Note that smaller intervals will result in higher fake keystroke
packet rates.',
        'type' => 'leaf',
        'upstream_default' => 'interval:20',
        'value_type' => 'uniline'
      },
      'PasswordAuthentication',
      {
        'description' => 'Specifies whether to use password authentication. The argument to this keyword
must be B<yes> (the default) or B<no>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PermitLocalCommand',
      {
        'description' => 'Allow local command execution via the B<LocalCommand> option or using the B<!>
I<command> escape sequence in L<ssh(1)>. The argument must be B<yes> or B<no>
(the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PermitRemoteOpen',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies the destinations to which remote TCP port forwarding is permitted
when B<RemoteForward> is used as a SOCKS proxy. The forwarding specification
must be one of the following forms:

B<PermitRemoteOpen> I<host : port> B<PermitRemoteOpen> I<IPv4_addr : port>
B<PermitRemoteOpen> I<[ IPv6_addr ] : port>

Multiple forwards may be specified by separating them with whitespace. An
argument of B<any> can be used to remove all restrictions and permit any
forwarding requests. An argument of B<none> can be used to prohibit all
forwarding requests. The wildcard \'*\' can be used for host or port to allow all
hosts or ports respectively. Otherwise, no pattern matching or address lookups
are performed on supplied names.',
        'type' => 'list'
      },
      'PKCS11Provider',
      {
        'description' => 'Specifies which PKCS#11 provider to use or B<none> to indicate that no provider
should be used (the default). The argument to this keyword is a path to the
PKCS#11 shared library L<ssh(1)> should use to communicate with a PKCS#11 token
providing keys for user authentication.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Port',
      {
        'description' => 'Specifies the port number to connect on the remote host. The default is 22.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PreferredAuthentications',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline',
          'warn_unless_match' => {
            '^(gssapi-with-mic|hostbased|publickey|keyboard-interactive|password)$' => {
              'msg' => 'Unexpected authentication method: \'C<$_>\'. Expected one of
C<gssapi-with-mic>, C<hostbased>, C<publickey>,
C<keyboard-interactive> or C<password>
'
            }
          }
        },
        'description' => 'Specifies the order in which the client should try authentication methods. This
allows a client to prefer one method (e.g. B<keyboard-interactive> over another
method (e.g. B<password )> The default is: gssapi-with-mic, hostbased,
publickey, keyboard-interactive, password',
        'type' => 'list'
      },
      'ProxyCommand',
      {
        'description' => 'Specifies the command to use to connect to the server. The command string
extends to the end of the line, and is executed using the user\'s shell \'exec\'
directive to avoid a lingering shell process.

Arguments to B<ProxyCommand> accept the tokens described in the I<TOKENS>
section. The command can be basically anything, and should read from its
standard input and write to its standard output. It should eventually connect
an L<sshd(8)> server running on some machine, or execute B<sshd -i> somewhere.
Host key management will be done using the B<Hostname> of the host being
connected (defaulting to the name typed by the user). Setting the command to
B<none> disables this option entirely. Note that B<CheckHostIP> is not
available for connects with a proxy command.

This directive is useful in conjunction with L<nc(1)> and its proxy support.
For example, the following directive would connect via an HTTP proxy at
192.0.2.0: ProxyCommand /usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ProxyJump',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies one or more jump proxies as either [I<user > B<@> ] I<host> [: B<>
I<port> ] or an ssh URI . Multiple proxies may be separated by comma characters
and will be visited sequentially. Setting this option will cause L<ssh(1)> to
connect to the target host by first making a L<ssh(1)> connection to the
specified B<ProxyJump> host and then establishing a TCP forwarding to the
ultimate target from there. Setting the host to B<none> disables this option
entirely.

Note that this option will compete with the B<ProxyCommand> option - whichever
is specified first will prevent later instances of the other from taking
effect.

Note also that the configuration for the destination host (either supplied via
the command-line or the configuration file) is not generally applied to jump
hosts. ~/.ssh/config should be used if specific configuration is required for
jump hosts.',
        'type' => 'list'
      },
      'ProxyUseFdpass',
      {
        'description' => 'Specifies that B<ProxyCommand> will pass a connected file descriptor back to
L<ssh(1)> instead of continuing to execute and pass data. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PubkeyAcceptedAlgorithms',
      {
        'description' => 'Specifies the signature algorithms that will be used for public key
authentication as a comma-separated list of patterns. If the specified list
begins with a \'+\' character, then the algorithms after it will be appended to
the default instead of replacing it. If the specified list begins with a \'-\'
character, then the specified algorithms (including wildcards) will be removed
from the default set instead of replacing them. If the specified list begins
with a \'^\' character, then the specified algorithms will be placed at the head
of the default set. The default for this option is:
ssh-ed25519-cert-v01@openssh.com, ecdsa-sha2-nistp256-cert-v01@openssh.com,
ecdsa-sha2-nistp384-cert-v01@openssh.com,
ecdsa-sha2-nistp521-cert-v01@openssh.com, sk-ssh-ed25519-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com, rsa-sha2-512-cert-v01@openssh.com,
rsa-sha2-256-cert-v01@openssh.com, ssh-ed25519, ecdsa-sha2-nistp256,
ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ssh-ed25519@openssh.com,
sk-ecdsa-sha2-nistp256@openssh.com, rsa-sha2-512, rsa-sha2-256

The list of available signature algorithms may also be obtained using Qq ssh -Q
PubkeyAcceptedAlgorithms .',
        'migrate_from' => {
          'formula' => '$old',
          'variables' => {
            'old' => '- PubkeyAcceptedKeyTypes'
          }
        },
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PubkeyAuthentication',
      {
        'choice' => [
          'host-bound',
          'no',
          'unbound',
          'yes'
        ],
        'description' => 'Specifies whether to try public key authentication. The argument to this
keyword must be B<yes> (the default), B<no> B<unbound> or B<host-bound> The
final two options enable public key authentication while respectively disabling
or enabling the OpenSSH host-bound authentication protocol extension required
for restricted ssh-agent1 forwarding.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'enum'
      },
      'RekeyLimit',
      {
        'description' => 'Specifies the maximum amount of data that may be transmitted or received before
the session key is renegotiated, optionally followed by a maximum amount of
time that may pass before the session key is renegotiated. The first argument
is specified in bytes and may have a suffix of \'K\' \'M\' or \'G\' to indicate
Kilobytes, Megabytes, or Gigabytes, respectively. The default is between \'1G\'
and \'4G\' depending on the cipher. The optional second value is specified in
seconds and may use any of the units documented in the TIME FORMATS section of
sshd_config5. The default value for B<RekeyLimit> is B<default none> which
means that rekeying is performed after the cipher\'s default amount of data has
been sent or received and no time based rekeying is done.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RemoteCommand',
      {
        'description' => 'Specifies a command to execute on the remote machine after successfully
connecting to the server. The command string extends to the end of the line,
and is executed with the user\'s shell. Arguments to B<RemoteCommand> accept the
tokens described in the I<TOKENS> section.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'RemoteForward',
      {
        'cargo' => {
          'config_class_name' => 'Ssh::PortForward',
          'type' => 'node'
        },
        'description' => 'Specifies that a TCP port on the remote machine be forwarded over the secure
channel. The remote port may either be forwarded to a specified host and port
from the local machine, or may act as a SOCKS 4/5 proxy that allows a remote
client to connect to arbitrary destinations from the local machine. The first
argument is the listening specification and may be [I<bind_address : port> ]
or, if the remote host supports it, a Unix domain socket path. If forwarding to
a specific destination then the second argument must be I<host : > B<>
I<hostport> or a Unix domain socket path, otherwise if no destination argument
is specified then the remote forwarding will be established as a SOCKS proxy.
When acting as a SOCKS proxy, the destination of the connection can be
restricted by B<PermitRemoteOpen>

IPv6 addresses can be specified by enclosing addresses in square brackets.
Multiple forwardings may be specified, and additional forwardings can be given
on the command line. Privileged ports can be forwarded only when logging in as
root on the remote machine. Unix domain socket paths may use the tokens
described in the I<TOKENS> section and environment variables as described in
the I<ENVIRONMENT VARIABLES> section.

If the I<port> argument is 0, the listen port will be dynamically allocated on
the server and reported to the client at run time.

If the I<bind_address> is not specified, the default is to only bind to
loopback addresses. If the I<bind_address> is \'*\' or an empty string, then the
forwarding is requested to listen on all interfaces. Specifying a remote
I<bind_address> will only succeed if the server\'s B<GatewayPorts> option is
enabled (see sshd_config5).',
        'type' => 'list'
      },
      'RequestTTY',
      {
        'choice' => [
          'auto',
          'force',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether to request a pseudo-tty for the session. The argument may be
one of: B<no> (never request a TTY), B<yes> (always request a TTY when standard
input is a TTY), B<force> (always request a TTY) or B<auto> (request a TTY when
opening a login session). This option mirrors the -B<t> and -B<T> flags for
L<ssh(1)>.',
        'type' => 'leaf',
        'value_type' => 'enum'
      },
      'RequiredRSASize',
      {
        'description' => 'Specifies the minimum RSA key size (in bits) that L<ssh(1)> will accept. User
authentication keys smaller than this limit will be ignored. Servers that
present host keys smaller than this limit will cause the connection to be
terminated. The default is B<1024> bits. Note that this limit may only be
raised from the default.',
        'type' => 'leaf',
        'upstream_default' => '1024',
        'value_type' => 'integer'
      },
      'RevokedHostKeys',
      {
        'description' => 'Specifies revoked host public keys. Keys listed in this file will be refused
for host authentication. Note that if this file does not exist or is not
readable, then host authentication will be refused for all hosts. Keys may be
specified as a text file, listing one public key per line, or as an OpenSSH Key
Revocation List (KRL) as generated by ssh-keygen1. For more information on
KRLs, see the KEY REVOCATION LISTS section in ssh-keygen1. Arguments to
B<RevokedHostKeys> may use the tilde syntax to refer to a user\'s home
directory, the tokens described in the I<TOKENS> section and environment
variables as described in the I<ENVIRONMENT VARIABLES> section.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'SecurityKeyProvider',
      {
        'description' => 'Specifies a path to a library that will be used when loading any FIDO
authenticator-hosted keys, overriding the default of using the built-in USB HID
support.

If the specified value begins with a \'$\' character, then it will be treated as
an environment variable containing the path to the library.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'SendEnv',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies what variables from the local L<environ(7)> should be sent to the
server. The server must also support it, and the server must be configured to
accept these environment variables. Note that the B<TERM> environment variable
is always sent whenever a pseudo-terminal is requested as it is required by the
protocol. Refer to B<AcceptEnv> in sshd_config5 for how to configure the
server. Variables are specified by name, which may contain wildcard characters.
Multiple environment variables may be separated by whitespace or spread across
multiple B<SendEnv> directives.

See I<PATTERNS> for more information on patterns.

It is possible to clear previously set B<SendEnv> variable names by prefixing
patterns with - The default is not to send any environment variables.',
        'type' => 'list'
      },
      'ServerAliveCountMax',
      {
        'description' => 'Sets the number of server alive messages (see below) which may be sent without
L<ssh(1)> receiving any messages back from the server. If this threshold is
reached while server alive messages are being sent, ssh will disconnect from
the server, terminating the session. It is important to note that the use of
server alive messages is very different from B<TCPKeepAlive> (below). The
server alive messages are sent through the encrypted channel and therefore will
not be spoofable. The TCP keepalive option enabled by B<TCPKeepAlive> is
spoofable. The server alive mechanism is valuable when the client or server
depend on knowing when a connection has become unresponsive.

The default value is 3. If, for example, B<ServerAliveInterval> (see below) is
set to 15 and B<ServerAliveCountMax> is left at the default, if the server
becomes unresponsive, ssh will disconnect after approximately 45 seconds.',
        'type' => 'leaf',
        'upstream_default' => '3',
        'value_type' => 'integer'
      },
      'ServerAliveInterval',
      {
        'description' => 'Sets a timeout interval in seconds after which if no data has been received
from the server, L<ssh(1)> will send a message through the encrypted channel to
request a response from the server. The default is 0, indicating that these
messages will not be sent to the server, or 300 if the B<BatchMode> option is
set (Debian-specific). B<ProtocolKeepAlives> and B<SetupTimeOut> are
Debian-specific compatibility aliases for this option.',
        'type' => 'leaf',
        'upstream_default' => '0',
        'value_type' => 'integer'
      },
      'SessionType',
      {
        'choice' => [
          'default',
          'none',
          'subsystem'
        ],
        'description' => 'May be used to either request invocation of a subsystem on the remote system,
or to prevent the execution of a remote command at all. The latter is useful
for just forwarding ports. The argument to this keyword must be B<none> (same
as the -B<N> option), B<subsystem> (same as the -B<s> option) or B<default>
(shell or command execution).',
        'type' => 'leaf',
        'value_type' => 'enum'
      },
      'SetEnv',
      {
        'description' => 'Directly specify one or more environment variables and their contents to be
sent to the server. Similarly to B<SendEnv> with the exception of the B<TERM>
variable, the server must be prepared to accept the environment variable.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'StdinNull',
      {
        'description' => 'Redirects stdin from /dev/null (actually, prevents reading from stdin). Either
this or the equivalent -B<n> option must be used when B<ssh> is run in the
background. The argument to this keyword must be B<yes> (same as the -B<n>
option) or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
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
exists and B<StreamLocalBindUnlink> is not enabled, B<ssh> will be unable to
forward the port to the Unix-domain socket file. This option is only used for
port forwarding to a Unix-domain socket file.

The argument must be B<yes> or B<no> (the default).',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'StrictHostKeyChecking',
      {
        'choice' => [
          'yes',
          'accept-new',
          'no',
          'off',
          'ask'
        ],
        'description' => 'If this flag is set to B<yes> L<ssh(1)> will never automatically add host keys
to the ~/.ssh/known_hosts file, and refuses to connect to hosts whose host key
has changed. This provides maximum protection against man-in-the-middle (MITM)
attacks, though it can be annoying when the /etc/ssh/ssh_known_hosts file is
poorly maintained or when connections to new hosts are frequently made. This
option forces the user to manually add all new hosts.

If this flag is set to B<accept-new> then ssh will automatically add new host
keys to the user\'s known_hosts file, but will not permit connections to hosts
with changed host keys. If this flag is set to B<no> or B<off> ssh will
automatically add new host keys to the user known hosts files and allow
connections to hosts with changed hostkeys to proceed, subject to some
restrictions. If this flag is set to B<ask> (the default), new host keys will
be added to the user known host files only after the user has confirmed that is
what they really want to do, and ssh will refuse to connect to hosts whose host
key has changed. The host keys of known hosts will be verified automatically in
all cases.',
        'type' => 'leaf',
        'upstream_default' => 'ask',
        'value_type' => 'enum'
      },
      'SyslogFacility',
      {
        'choice' => [
          'AUTH',
          'DAEMON',
          'LOCAL0',
          'LOCAL1',
          'LOCAL2',
          'LOCAL3',
          'LOCAL4',
          'LOCAL5',
          'LOCAL6',
          'LOCAL7',
          'USER'
        ],
        'description' => 'Gives the facility code that is used when logging messages from L<ssh(1)>. The
possible values are: DAEMON, USER, AUTH, LOCAL0, LOCAL1, LOCAL2, LOCAL3,
LOCAL4, LOCAL5, LOCAL6, LOCAL7. The default is USER.',
        'type' => 'leaf',
        'upstream_default' => 'USER',
        'value_type' => 'enum'
      },
      'TCPKeepAlive',
      {
        'description' => 'Specifies whether the system should send TCP keepalive messages to the other
side. If they are sent, death of the connection or crash of one of the machines
will be properly noticed. This option only uses TCP keepalives (as opposed to
using ssh level keepalives), so takes a long time to notice when the connection
dies. As such, you probably want the B<ServerAliveInterval> option as well.
However, this means that connections will die if the route is down temporarily,
and some people find it annoying.

The default is B<yes> (to send TCP keepalive messages), and the client will
notice if the network goes down or the remote host dies. This is important in
scripts, and many users want it too.

To disable TCP keepalive messages, the value should be set to B<no> See also
B<ServerAliveInterval> for protocol-level keepalives.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'Tag',
      {
        'description' => 'Specify a configuration tag name that may be later used by a B<Match> directive
to select a block of configuration.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Tunnel',
      {
        'choice' => [
          'ethernet',
          'no',
          'point-to-point',
          'yes'
        ],
        'description' => 'Request L<tun(4)> device forwarding between the client and the server. The
argument must be B<yes> B<point-to-point> (layer 3), B<ethernet> (layer 2), or
B<no> (the default). Specifying B<yes> requests the default tunnel mode, which
is B<point-to-point>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'TunnelDevice',
      {
        'description' => 'Specifies the L<tun(4)> devices to open on the client (I<local_tun> ) and the
server (I<remote_tun> )

The argument must be I<local_tun > [: I<remote_tun> ] The devices may be
specified by numerical ID or the keyword B<any> which uses the next available
tunnel device. If I<remote_tun> is not specified, it defaults to B<any> The
default is B<any:any>',
        'type' => 'leaf',
        'upstream_default' => 'any:any',
        'value_type' => 'uniline'
      },
      'UpdateHostKeys',
      {
        'choice' => [
          'ask',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether L<ssh(1)> should accept notifications of additional hostkeys
from the server sent after authentication has completed and add them to
B<UserKnownHostsFile> The argument must be B<yes> B<no> or B<ask> This option
allows learning alternate hostkeys for a server and supports graceful key
rotation by allowing a server to send replacement public keys before old ones
are removed.

Additional hostkeys are only accepted if the key used to authenticate the host
was already trusted or explicitly accepted by the user, the host was
authenticated via B<UserKnownHostsFile> (i.e. not B<GlobalKnownHostsFile> and
the host was authenticated using a plain key and not a certificate.

B<UpdateHostKeys> is enabled by default if the user has not overridden the
default B<UserKnownHostsFile> setting and has not enabled B<VerifyHostKeyDNS>
otherwise B<UpdateHostKeys> will be set to B<no>

If B<UpdateHostKeys> is set to B<ask> then the user is asked to confirm the
modifications to the known_hosts file. Confirmation is currently incompatible
with B<ControlPersist> and will be disabled if it is enabled.

Presently, only L<sshd(8)> from OpenSSH 6.8 and greater support the Qq
hostkeys@openssh.com protocol extension used to inform the client of all the
server\'s hostkeys.',
        'type' => 'leaf',
        'value_type' => 'enum'
      },
      'User',
      {
        'description' => 'Specifies the user to log in as. This can be useful when a different user name
is used on different machines. This saves the trouble of having to remember to
give the user name on the command line.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'UserKnownHostsFile',
      {
        'cargo' => {
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Specifies one or more files to use for the user host key database, separated by
whitespace. Each filename may use tilde notation to refer to the user\'s home
directory, the tokens described in the I<TOKENS> section and environment
variables as described in the I<ENVIRONMENT VARIABLES> section. A value of
B<none> causes L<ssh(1)> to ignore any user-specific known hosts files. The
default is ~/.ssh/known_hosts ~/.ssh/known_hosts2',
        'type' => 'list'
      },
      'VerifyHostKeyDNS',
      {
        'choice' => [
          'ask',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether to verify the remote key using DNS and SSHFP resource
records. If this option is set to B<yes> the client will implicitly trust keys
that match a secure fingerprint from DNS. Insecure fingerprints will be handled
as if this option was set to B<ask> If this option is set to B<ask> information
on fingerprint match will be displayed, but the user will still need to confirm
new host keys according to the B<StrictHostKeyChecking> option. The default is
B<no>

See also I<VERIFYING HOST KEYS> in L<ssh(1)>.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'enum'
      },
      'VisualHostKey',
      {
        'description' => 'If this flag is set to B<yes> an ASCII art representation of the remote host
key fingerprint is printed in addition to the fingerprint string at login and
for unknown host keys. If this flag is set to B<no> (the default), no
fingerprint strings are printed at login and only the fingerprint string will
be printed for unknown host keys.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'uniline'
      },
      'XAuthLocation',
      {
        'description' => 'Specifies the full pathname of the L<xauth(1)> program. The default is
/usr/bin/xauth',
        'type' => 'leaf',
        'upstream_default' => '/usr/bin/xauth',
        'value_type' => 'uniline'
      },
      'FallBackToRsh',
      {
        'description' => 'This parameter is now ignored by Ssh',
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostbasedKeyTypes',
      {
        'description' => 'This parameter is now ignored by Ssh',
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PubkeyAcceptedKeyTypes',
      {
        'description' => 'This parameter is now ignored by Ssh',
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'UseRsh',
      {
        'description' => 'This parameter is now ignored by Ssh',
        'status' => 'deprecated',
        'type' => 'leaf',
        'value_type' => 'uniline'
      }
    ],
    'generated_by' => 'parse-man.pl from ssh_system  9.8p1 doc',
    'license' => 'LGPL2',
    'name' => 'Ssh::HostElement'
  }
]
;

