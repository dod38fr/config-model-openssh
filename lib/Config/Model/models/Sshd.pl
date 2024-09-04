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
      'AddressFamily',
      {
        'choice' => [
          'any',
          'inet',
          'inet6'
        ],
        'description' => 'Specifies which address family should be used by L<sshd(8)>. Valid arguments
are B<any> (the default), B<inet> (use IPv4 only), or B<inet6> (use IPv6 only).',
        'type' => 'leaf',
        'upstream_default' => 'any',
        'value_type' => 'enum'
      },
      'Ciphers',
      {
        'description' => 'Specifies the ciphers allowed. Multiple ciphers must be comma-separated. If the
specified list begins with a \'+\' character, then the specified ciphers will be
appended to the default set instead of replacing them. If the specified list
begins with a \'-\' character, then the specified ciphers (including wildcards)
will be removed from the default set instead of replacing them. If the
specified list begins with a \'^\' character, then the specified ciphers will be
placed at the head of the default set.

The supported ciphers are:

B<3des-cbc> B<aes128-cbc> B<aes192-cbc> B<aes256-cbc> B<aes128-ctr>
B<aes192-ctr> B<aes256-ctr> B<aes128-gcm@openssh.com> B<aes256-gcm@openssh.com>
B<chacha20-poly1305@openssh.com>

The default is: chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr,
aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com

The list of available ciphers may also be obtained using Qq ssh -Q cipher .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Compression',
      {
        'choice' => [
          'delayed',
          'no',
          'yes'
        ],
        'description' => 'Specifies whether compression is enabled after the user has authenticated
successfully. The argument must be B<yes> B<delayed> (a legacy synonym for
B<yes> or B<no> The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'enum'
      },
      'DebianBanner',
      {
        'description' => 'Specifies whether the distribution-specified extra version suffix is included
during initial protocol handshake. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
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
        'description' => 'Specifies the hash algorithm used when logging key fingerprints. Valid options
are: B<md5> and B<sha256> The default is B<sha256>',
        'type' => 'leaf',
        'upstream_default' => 'sha256',
        'value_type' => 'enum'
      },
      'GSSAPICleanupCredentials',
      {
        'description' => 'Specifies whether to automatically destroy the user\'s credentials cache on
logout. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GSSAPIKeyExchange',
      {
        'description' => 'Specifies whether key exchange based on GSSAPI is allowed. GSSAPI key exchange
doesn\'t rely on ssh keys to verify host identity. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GSSAPIStrictAcceptorCheck',
      {
        'description' => 'Determines whether to be strict about the identity of the GSSAPI acceptor a
client authenticates against. If set to B<yes> then the client must
authenticate against the host service on the current hostname. If set to B<no>
then the client may authenticate against any service key stored in the
machine\'s default store. This facility is provided to assist with operation on
multi homed machines. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GSSAPIStoreCredentialsOnRekey',
      {
        'description' => 'Controls whether the user\'s GSSAPI credentials should be updated following a
successful connection rekeying. This option can be used to accepted renewed or
updated credentials from a compatible client. The default is \'\'no\'\'

For this to work B<GSSAPIKeyExchange> needs to be enabled in the server and
also used by the client.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'GSSAPIKexAlgorithms',
      {
        'description' => 'The list of key exchange algorithms that are accepted by GSSAPI key exchange.
Possible values are gss-gex-sha1-, gss-group1-sha1-, gss-group14-sha1-,
gss-group14-sha256-, gss-group16-sha512-, gss-nistp256-sha256-,
gss-curve25519-sha256-

The default is \'\'gss-group14-sha256-, gss-group16-sha512-,
gss-nistp256-sha256-, gss-curve25519-sha256-, gss-gex-sha1-,
gss-group14-sha1-\'\' This option only applies to connections using GSSAPI.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostCertificate',
      {
        'description' => 'Specifies a file containing a public host certificate. The certificate\'s public
key must match a private host key already specified by B<HostKey> The default
behaviour of L<sshd(8)> is not to load any certificates.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostKey',
      {
        'description' => 'Specifies a file containing a private host key used by SSH. The defaults are
/etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ed25519_key and
/etc/ssh/ssh_host_rsa_key

Note that L<sshd(8)> will refuse to use a file if it is group/world-accessible
and that the B<HostKeyAlgorithms> option restricts which of the keys are
actually used by L<sshd(8)>.

It is possible to have multiple host key files. It is also possible to specify
public host key files instead. In this case operations on the private key will
be delegated to an ssh-agent1.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostKeyAgent',
      {
        'description' => 'Identifies the UNIX-domain socket used to communicate with an agent that has
access to the private host keys. If the string Qq SSH_AUTH_SOCK is specified,
the location of the socket will be read from the B<SSH_AUTH_SOCK> environment
variable.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'HostKeyAlgorithms',
      {
        'description' => 'Specifies the host key signature algorithms that the server offers. The default
for this option is: ssh-ed25519-cert-v01@openssh.com,
ecdsa-sha2-nistp256-cert-v01@openssh.com,
ecdsa-sha2-nistp384-cert-v01@openssh.com,
ecdsa-sha2-nistp521-cert-v01@openssh.com, sk-ssh-ed25519-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com, rsa-sha2-512-cert-v01@openssh.com,
rsa-sha2-256-cert-v01@openssh.com, ssh-ed25519, ecdsa-sha2-nistp256,
ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ssh-ed25519@openssh.com,
sk-ecdsa-sha2-nistp256@openssh.com, rsa-sha2-512, rsa-sha2-256

The list of available signature algorithms may also be obtained using Qq ssh -Q
HostKeyAlgorithms .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'IgnoreUserKnownHosts',
      {
        'description' => 'Specifies whether L<sshd(8)> should ignore the user\'s ~/.ssh/known_hosts during
B<HostbasedAuthentication> and use only the system-wide known hosts file
/etc/ssh/ssh_known_hosts The default is \'\'no\'\'',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KerberosGetAFSToken',
      {
        'description' => 'If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS
token before accessing the user\'s home directory. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KerberosOrLocalPasswd',
      {
        'description' => 'If password authentication through Kerberos fails then the password will be
validated via any additional local mechanism such as /etc/passwd The default is
B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KerberosTicketCleanup',
      {
        'description' => 'Specifies whether to automatically destroy the user\'s ticket cache file on
logout. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'KexAlgorithms',
      {
        'description' => 'Specifies the permitted KEX (Key Exchange) algorithms that the server will
offer to clients. The ordering of this list is not important, as the client
specifies the preference order. Multiple algorithms must be comma-separated.

If the specified list begins with a \'+\' character, then the specified
algorithms will be appended to the default set instead of replacing them. If
the specified list begins with a \'-\' character, then the specified algorithms
(including wildcards) will be removed from the default set instead of replacing
them. If the specified list begins with a \'^\' character, then the specified
algorithms will be placed at the head of the default set.

The supported algorithms are:

B<curve25519-sha256> B<curve25519-sha256@libssh.org>
B<diffie-hellman-group1-sha1> B<diffie-hellman-group14-sha1>
B<diffie-hellman-group14-sha256> B<diffie-hellman-group16-sha512>
B<diffie-hellman-group18-sha512> B<diffie-hellman-group-exchange-sha1>
B<diffie-hellman-group-exchange-sha256> B<ecdh-sha2-nistp256>
B<ecdh-sha2-nistp384> B<ecdh-sha2-nistp521>
B<sntrup761x25519-sha512@openssh.com>

The default is: sntrup761x25519-sha512@openssh.com, curve25519-sha256,
curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384,
ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256,
diffie-hellman-group16-sha512, diffie-hellman-group18-sha512,
diffie-hellman-group14-sha256

The list of supported key exchange algorithms may also be obtained using Qq ssh
-Q KexAlgorithms .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'ListenAddress',
      {
        'description' => 'Specifies the local addresses L<sshd(8)> should listen on. The following forms
may be used:

B<ListenAddress> I<hostname | address> B<ListenAddress> I<hostname : port>
B<ListenAddress> I<IPv4_address : port> B<ListenAddress> [I<hostname | address
: port> ]

If I<port> is not specified, sshd will listen on the address and all B<Port>
options specified. The default is to listen on all local addresses. Multiple
B<ListenAddress> options are permitted.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'LoginGraceTime',
      {
        'description' => 'The server disconnects after this time if the user has not successfully logged
in. If the value is 0, there is no time limit. The default is 120 seconds.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'LogVerbose',
      {
        'description' => 'Specify one or more overrides to B<LogLevel> An override consists of a pattern
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
        'description' => 'Specifies the available MAC (message authentication code) algorithms.

The MAC algorithm is used for data integrity protection. Multiple algorithms
must be comma-separated. If the specified list begins with a \'+\' character,
then the specified algorithms will be appended to the default set instead of
replacing them. If the specified list begins with a \'-\' character, then the
specified algorithms (including wildcards) will be removed from the default set
instead of replacing them. If the specified list begins with a \'^\' character,
then the specified algorithms will be placed at the head of the default set.

The algorithms that contain Qq -etm calculate the MAC after encryption
(encrypt-then-mac). These are considered safer and their use recommended. The
supported MACs are:

B<hmac-md5> B<hmac-md5-96> B<hmac-sha1> B<hmac-sha1-96> B<hmac-sha2-256>
B<hmac-sha2-512> B<umac-64@openssh.com> B<umac-128@openssh.com>
B<hmac-md5-etm@openssh.com> B<hmac-md5-96-etm@openssh.com>
B<hmac-sha1-etm@openssh.com> B<hmac-sha1-96-etm@openssh.com>
B<hmac-sha2-256-etm@openssh.com> B<hmac-sha2-512-etm@openssh.com>
B<umac-64-etm@openssh.com> B<umac-128-etm@openssh.com>

The default is: umac-64-etm@openssh.com, umac-128-etm@openssh.com,
hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com,
hmac-sha1-etm@openssh.com, umac-64@openssh.com, umac-128@openssh.com,
hmac-sha2-256, hmac-sha2-512, hmac-sha1

The list of available MAC algorithms may also be obtained using Qq ssh -Q mac .',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'Match',
      {
        'cargo' => {
          'config_class_name' => 'Sshd::MatchBlock',
          'type' => 'node'
        },
        'description' => 'Introduces a conditional block. If all of the criteria on the B<Match> line are
satisfied, the keywords on the following lines override those set in the global
section of the config file, until either another B<Match> line or the end of
the file. If a keyword appears in multiple B<Match> blocks that are satisfied,
only the first instance of the keyword is applied.

The arguments to B<Match> are one or more criteria-pattern pairs or the single
token B<All> which matches all criteria. The available criteria are B<User>
B<Group> B<Host> B<LocalAddress> B<LocalPort> and B<Address>

The match patterns may consist of single entries or comma-separated lists and
may use the wildcard and negation operators described in the I<PATTERNS>
section of ssh_config5.

The patterns in an B<Address> criteria may additionally contain addresses to
match in CIDR address/masklen format, such as 192.0.2.0/24 or 2001:db8::/32.
Note that the mask length provided must be consistent with the address - it is
an error to specify a mask length that is too long for the address or one with
bits set in this host portion of the address. For example, 192.0.2.0/33 and
192.0.2.0/8, respectively.

Only a subset of keywords may be used on the lines following a B<Match>
keyword. Available keywords are B<AcceptEnv> B<AllowAgentForwarding>
B<AllowGroups> B<AllowStreamLocalForwarding> B<AllowTcpForwarding>
B<AllowUsers> B<AuthenticationMethods> B<AuthorizedKeysCommand>
B<AuthorizedKeysCommandUser> B<AuthorizedKeysFile>
B<AuthorizedPrincipalsCommand> B<AuthorizedPrincipalsCommandUser>
B<AuthorizedPrincipalsFile> B<Banner> B<CASignatureAlgorithms>
B<ChannelTimeout> B<ChrootDirectory> B<ClientAliveCountMax>
B<ClientAliveInterval> B<DenyGroups> B<DenyUsers> B<DisableForwarding>
B<ExposeAuthInfo> B<ForceCommand> B<GatewayPorts> B<GSSAPIAuthentication>
B<HostbasedAcceptedAlgorithms> B<HostbasedAuthentication>
B<HostbasedUsesNameFromPacketOnly> B<IgnoreRhosts> B<Include> B<IPQoS>
B<KbdInteractiveAuthentication> B<KerberosAuthentication> B<LogLevel>
B<MaxAuthTries> B<MaxSessions> B<PAMServiceName> B<PasswordAuthentication>
B<PermitEmptyPasswords> B<PermitListen> B<PermitOpen> B<PermitRootLogin>
B<PermitTTY> B<PermitTunnel> B<PermitUserRC> B<PubkeyAcceptedAlgorithms>
B<PubkeyAuthentication> B<PubkeyAuthOptions> B<RekeyLimit> B<RevokedKeys>
B<SetEnv> B<StreamLocalBindMask> B<StreamLocalBindUnlink> B<TrustedUserCAKeys>
B<UnusedConnectionTimeout> B<X11DisplayOffset> B<X11Forwarding> and
B<X11UseLocalhost>',
        'type' => 'list'
      },
      'MaxStartups',
      {
        'description' => 'Specifies the maximum number of concurrent unauthenticated connections to the
SSH daemon. Additional connections will be dropped until authentication
succeeds or the B<LoginGraceTime> expires for a connection. The default is
10:30:100.

Alternatively, random early drop can be enabled by specifying the three colon
separated values start:rate:full (e.g. "10:30:60"). L<sshd(8)> will refuse
connection attempts with a probability of rate/100 (30%) if there are currently
start (10) unauthenticated connections. The probability increases linearly and
all connection attempts are refused if the number of unauthenticated
connections reaches full (60).',
        'type' => 'leaf',
        'upstream_default' => '10',
        'value_type' => 'uniline'
      },
      'ModuliFile',
      {
        'description' => 'Specifies the L<moduli(5)> file that contains the Diffie-Hellman groups used
for the \'\'diffie-hellman-group-exchange-sha1\'\' and
\'\'diffie-hellman-group-exchange-sha256\'\' key exchange methods. The default is
/etc/ssh/moduli',
        'type' => 'leaf',
        'upstream_default' => '/etc/ssh/moduli',
        'value_type' => 'uniline'
      },
      'PermitUserEnvironment',
      {
        'description' => 'Specifies whether ~/.ssh/environment and B<environment=> options in
~/.ssh/authorized_keys are processed by L<sshd(8)>. Valid options are B<yes>
B<no> or a pattern-list specifying which environment variable names to accept
(for example Qq LANG, LC_* ) . The default is B<no> Enabling environment
processing may enable users to bypass access restrictions in some
configurations using mechanisms such as B<LD_PRELOAD>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PerSourceMaxStartups',
      {
        'description' => 'Specifies the number of unauthenticated connections allowed from a given source
address, or \'\'none\'\' if there is no limit. This limit is applied in addition to
B<MaxStartups> whichever is lower. The default is B<none>',
        'type' => 'leaf',
        'upstream_default' => 'none',
        'value_type' => 'uniline'
      },
      'PerSourceNetBlockSize',
      {
        'description' => 'Specifies the number of bits of source address that are grouped together for
the purposes of applying PerSourceMaxStartups limits. Values for IPv4 and
optionally IPv6 may be specified, separated by a colon. The default is
B<32:128> which means each address is considered individually.',
        'type' => 'leaf',
        'upstream_default' => '32:128',
        'value_type' => 'uniline'
      },
      'PerSourcePenalties',
      {
        'description' => 'Controls penalties for various conditions that may represent attacks on
L<sshd(8)>. If a penalty is enforced against a client then its source address
and any others in the same network, as defined by B<PerSourceNetBlockSize> will
be refused connection for a period.

A penalty doesn\'t affect concurrent connections in progress, but multiple
penalties from the same source from concurrent connections will accumulate up
to a maximum. Conversely, penalties are not applied until a minimum threshold
time has been accumulated.

Penalties are enabled by default with the default settings listed below but may
disabled using the B<off> keyword. The defaults may be overridden by specifying
one or more of the keywords below, separated by whitespace. All keywords accept
arguments, e.g. Qq crash:2m .

B<crash:duration> Specifies how long to refuse clients that cause a crash of
L<sshd(8)>(default:90s). B<authfail:duration> Specifies how long to refuse
clients that disconnect after making one or more unsuccessful authentication
attempts (default: 5s). B<noauth:duration> Specifies how long to refuse clients
that disconnect without attempting authentication (default: 1s). This timeout
should be used cautiously otherwise it may penalise legitimate scanning tools
such as ssh-keyscan1. B<grace-exceeded:duration> Specifies how long to refuse
clients that fail to authenticate after B<LoginGraceTime> (default: 20s).
B<max:duration> Specifies the maximum time a particular source address range
will be refused access for (default: 10m). Repeated penalties will accumulate
up to this maximum. B<min:duration> Specifies the minimum penalty that must
accrue before enforcement begins (default: 15s). B<max-sources4:number ,
max-sources6:number> Specifies the maximum number of client IPv4 and IPv6
address ranges to track for penalties (default: 65536 for both).
B<overflow:mode> Controls how the server behaves when B<max-sources4> or
B<max-sources6> is exceeded. There are two operating modes: B<deny-all> which
denies all incoming connections other than those exempted via
B<PerSourcePenaltyExemptList> until a penalty expires, and B<permissive> which
allows new connections by removing existing penalties early (default:
permissive). Note that client penalties below the B<min> threshold count
against the total number of tracked penalties. IPv4 and IPv6 addresses are
tracked separately, so an overflow in one will not affect the other.
B<overflow6:mode> Allows specifying a different overflow mode for IPv6
addresses. The default it to use the same overflow mode as was specified for
IPv4.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PerSourcePenaltyExemptList',
      {
        'description' => 'Specifies a comma-separated list of addresses to exempt from penalties. This
list may contain wildcards and CIDR address/masklen ranges. Note that the mask
length provided must be consistent with the address - it is an error to specify
a mask length that is too long for the address or one with bits set in this
host portion of the address. For example, 192.0.2.0/33 and 192.0.2.0/8,
respectively. The default is not to exempt any addresses.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PidFile',
      {
        'description' => 'Specifies the file that contains the process ID of the SSH daemon, or B<none>
to not write one. The default is /run/sshd.pid',
        'type' => 'leaf',
        'upstream_default' => '/run/sshd',
        'value_type' => 'uniline'
      },
      'Port',
      {
        'description' => 'Specifies the port number that L<sshd(8)> listens on. The default is 22.
Multiple options of this type are permitted. See also B<ListenAddress>',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'PrintLastLog',
      {
        'description' => 'Specifies whether L<sshd(8)> should print the date and time of the last user
login when a user logs in interactively. The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'PrintMotd',
      {
        'description' => 'Specifies whether L<sshd(8)> should print /etc/motd when a user logs in
interactively. (On some systems it is also printed by the shell, /etc/profile
or equivalent.) The default is B<yes>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'RequiredRSASize',
      {
        'description' => 'Specifies the minimum RSA key size (in bits) that L<sshd(8)> will accept. User
and host-based authentication keys smaller than this limit will be refused. The
default is B<1024> bits. Note that this limit may only be raised from the
default.',
        'type' => 'leaf',
        'upstream_default' => '1024',
        'value_type' => 'integer'
      },
      'SecurityKeyProvider',
      {
        'description' => 'Specifies a path to a library that will be used when loading FIDO
authenticator-hosted keys, overriding the default of using the built-in USB HID
support.',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'SshdSessionPath',
      {
        'description' => 'Overrides the default path to the B<sshd-session> binary that is invoked to
handle each connection. The default is /usr/lib/openssh/sshd-session This
option is intended for use by tests.',
        'type' => 'leaf',
        'upstream_default' => '/usr/lib/openssh/sshd',
        'value_type' => 'uniline'
      },
      'StrictModes',
      {
        'description' => 'Specifies whether L<sshd(8)> should check file modes and ownership of the
user\'s files and home directory before accepting login. This is normally
desirable because novices sometimes accidentally leave their directory or files
world-writable. The default is B<yes> Note that this does not apply to
B<ChrootDirectory> whose permissions and ownership are checked unconditionally.',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'Subsystem',
      {
        'cargo' => {
          'mandatory' => '1',
          'type' => 'leaf',
          'value_type' => 'uniline'
        },
        'description' => 'Configures an external subsystem (e.g. file transfer daemon). Arguments should
be a subsystem name and a command (with optional arguments) to execute upon
subsystem request.

The command B<sftp-server> implements the SFTP file transfer subsystem.

Alternately the name B<internal-sftp> implements an in-process SFTP server.
This may simplify configurations using B<ChrootDirectory> to force a different
filesystem root on clients. It accepts the same command line arguments as
B<sftp-server> and even though it is in-process, settings such as B<LogLevel>
or B<SyslogFacility> do not apply to it and must be set explicitly via command
line arguments.

By default no subsystems are defined.',
        'index_type' => 'string',
        'type' => 'hash'
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
        'description' => 'Gives the facility code that is used when logging messages from L<sshd(8)>. The
possible values are: DAEMON, USER, AUTH, LOCAL0, LOCAL1, LOCAL2, LOCAL3,
LOCAL4, LOCAL5, LOCAL6, LOCAL7. The default is AUTH.',
        'type' => 'leaf',
        'upstream_default' => 'AUTH',
        'value_type' => 'enum'
      },
      'TCPKeepAlive',
      {
        'description' => 'Specifies whether the system should send TCP keepalive messages to the other
side. If they are sent, death of the connection or crash of one of the machines
will be properly noticed. However, this means that connections will die if the
route is down temporarily, and some people find it annoying. On the other hand,
if TCP keepalives are not sent, sessions may hang indefinitely on the server,
leaving Qq ghost users and consuming server resources.

The default is B<yes> (to send TCP keepalive messages), and the server will
notice if the network goes down or the client host crashes. This avoids
infinitely hanging sessions.

To disable TCP keepalive messages, the value should be set to B<no>

This option was formerly called B<KeepAlive>',
        'type' => 'leaf',
        'upstream_default' => 'yes',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'UseDNS',
      {
        'description' => 'Specifies whether L<sshd(8)> should look up the remote host name, and to check
that the resolved host name for the remote IP address maps back to the very
same IP address.

If this option is set to B<no> (the default) then only addresses and not host
names may be used in ~/.ssh/authorized_keys B<from> and B<sshd_config> B<Match>
B<Host> directives.',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'UsePAM',
      {
        'description' => 'Enables the Pluggable Authentication Module interface. If set to B<yes> this
will enable PAM authentication using B<KbdInteractiveAuthentication> and
B<PasswordAuthentication> in addition to PAM account and session module
processing for all authentication types.

Because PAM keyboard-interactive authentication usually serves an equivalent
role to password authentication, you should disable either
B<PasswordAuthentication> or B<KbdInteractiveAuthentication>

If B<UsePAM> is enabled, you will not be able to run L<sshd(8)> as a non-root
user. The default is B<no>',
        'type' => 'leaf',
        'upstream_default' => 'no',
        'value_type' => 'boolean',
        'write_as' => [
          'no',
          'yes'
        ]
      },
      'VersionAddendum',
      {
        'description' => 'Optionally specifies additional text to append to the SSH protocol banner sent
by the server upon connection. The default is B<none>',
        'type' => 'leaf',
        'value_type' => 'uniline'
      },
      'XAuthLocation',
      {
        'description' => 'Specifies the full pathname of the L<xauth(1)> program, or B<none> to not use
one. The default is /usr/bin/xauth',
        'type' => 'leaf',
        'upstream_default' => '/usr/bin/xauth',
        'value_type' => 'uniline'
      }
    ],
    'generated_by' => 'parse-man.pl from sshd_system  9.8p1 doc',
    'include' => [
      'Sshd::MatchElement'
    ],
    'license' => 'LGPL2',
    'name' => 'Sshd',
    'rw_config' => {
      'backend' => 'OpenSsh::Sshd',
      'config_dir' => '/etc/ssh',
      'file' => 'sshd_config',
      'os_config_dir' => {
        'darwin' => '/etc'
      }
    }
  }
]
;

