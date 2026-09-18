#!/usr/bin/env perl

use strict;
use warnings;

use JSON::PP qw(decode_json encode_json);
use Getopt::Long qw(GetOptions);
use POSIX qw(strftime);
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use IO::Select;

# ============================================================
# KYGnus Firewall Check
# Read-only nftables security analyzer
#
# Version: 0.8.2
#
# Designed for:
#   Debian / antiX / Ubuntu / openSUSE / Rocky / RHEL
#
# No systemd dependency.
# No firewall changes are performed.
# ============================================================

my $VERSION = '0.8.2';

my %OPT = (
    summary  => 0,
    services => 0,
    findings => 0,
    rules    => 0,
    json     => 0,
    verbose  => 0,
);

GetOptions(
    'summary'   => \$OPT{summary},
    'services'  => \$OPT{services},
    'findings'  => \$OPT{findings},
    'rules'     => \$OPT{rules},
    'json'      => \$OPT{json},
    'verbose|v' => \$OPT{verbose},
    'version'   => sub {
        print "KYGnus Firewall Check $VERSION\n";
        exit 0;
    },
    'help|h' => sub {
        print_help();
        exit 0;
    },
) or do {
    print_help();
    exit 2;
};

# ============================================================
# Global state
# ============================================================

my @RULES;
my @CHAINS;
my @TABLES;
my @FINDINGS;
my @SERVICES;

my %TABLE_LOOKUP;
my %CHAIN_LOOKUP;
my %DUPLICATES;

my %COUNTERS = (
    rules          => 0,
    accept         => 0,
    drop           => 0,
    reject         => 0,
    return         => 0,
    queue          => 0,
    log            => 0,
    nat            => 0,
    masquerade     => 0,
    redirect       => 0,
    dnat           => 0,
    snat           => 0,
    established    => 0,
    related        => 0,
    invalid        => 0,
    tcp            => 0,
    udp            => 0,
    icmp           => 0,
    icmpv6         => 0,
    ipv4           => 0,
    ipv6           => 0,
    interfaces     => 0,
    source_ports   => 0,
    destination_ports => 0,
);

# ============================================================
# Generic type helpers
# ============================================================

sub is_hash {
    return defined($_[0]) && ref($_[0]) eq 'HASH';
}

sub is_array {
    return defined($_[0]) && ref($_[0]) eq 'ARRAY';
}

sub is_scalar_value {
    return defined($_[0]) && !ref($_[0]);
}

sub safe_string {
    my ($value) = @_;

    return '' unless defined $value;
    return '' if ref($value);

    return "$value";
}

sub safe_number {
    my ($value) = @_;

    return 0 unless defined $value;
    return 0 if ref($value);

    return 0 + $value if "$value" =~ /^-?\d+(?:\.\d+)?$/;

    return 0;
}

sub trim {
    my ($s) = @_;

    return '' unless defined $s;
    return '' if ref($s);

    $s =~ s/^\s+//;
    $s =~ s/\s+$//;

    return $s;
}

sub add_unique {
    my ($array_ref, $value) = @_;

    return unless is_array($array_ref);
    return unless defined $value;

    $value = safe_string($value);
    return unless length $value;

    for my $existing (@{$array_ref}) {
        return if defined($existing) && $existing eq $value;
    }

    push @{$array_ref}, $value;
}

sub severity_rank {
    my ($severity) = @_;

    return 4 if defined($severity) && $severity eq 'CRITICAL';
    return 3 if defined($severity) && $severity eq 'HIGH';
    return 2 if defined($severity) && $severity eq 'MEDIUM';
    return 1 if defined($severity) && $severity eq 'LOW';

    return 0;
}

# ============================================================
# Formatting
# ============================================================

sub format_number {
    my ($number) = @_;

    $number = 0 unless defined $number;
    return sprintf "%d", $number;
}

sub format_bytes {
    my ($bytes) = @_;

    $bytes = safe_number($bytes);

    return '0 B' if $bytes <= 0;

    my @units = (
        'B',
        'KiB',
        'MiB',
        'GiB',
        'TiB',
    );

    my $unit = 0;
    my $value = $bytes;

    while ($value >= 1024 && $unit < $#units) {
        $value /= 1024;
        $unit++;
    }

    return sprintf("%.1f %s", $value, $units[$unit]);
}

# ============================================================
# Help
# ============================================================

sub print_help {

    print <<'EOF';

KYGnus Firewall Check

Read-only nftables firewall security analyzer.

Usage:
    sudo perl firewall-check.pl
    sudo perl firewall-check.pl --summary
    sudo perl firewall-check.pl --services
    sudo perl firewall-check.pl --findings
    sudo perl firewall-check.pl --rules
    sudo perl firewall-check.pl --verbose
    sudo perl firewall-check.pl --json

Options:
    --summary       Show firewall summary
    --services      Show exposed services
    --findings      Show security findings
    --rules         Show parsed rules
    --json          Output JSON
    --verbose,-v    Verbose diagnostics
    --version       Show version
    --help,-h       Show help

The program does NOT modify nftables.

EOF
}

# ============================================================
# Command detection
# ============================================================

sub command_exists {
    my ($command) = @_;

    return 0 unless defined $command;
    return 0 if ref($command);

    for my $dir (split /:/, ($ENV{PATH} // '')) {

        next unless defined $dir;
        next unless length $dir;

        my $path = "$dir/$command";

        return 1 if -x $path;
    }

    return 0;
}

sub find_nft {

    my @candidates = (
        '/usr/sbin/nft',
        '/sbin/nft',
        '/usr/bin/nft',
        '/bin/nft',
    );

    for my $path (@candidates) {
        return $path if -x $path;
    }

    return 'nft' if command_exists('nft');

    return undef;
}

# ============================================================
# Privilege check
# ============================================================

sub check_privileges {

    return if $> == 0;

    print STDERR "[WARN] Not running as root.\n";
    print STDERR "[WARN] nftables may refuse access depending on system configuration.\n";
    print STDERR "[WARN] Try: sudo perl firewall-check.pl\n\n";
}

# ============================================================
# Execute nft safely
# ============================================================

sub run_nft {

    my $nft = find_nft();

    die "ERROR: nft command not found.\n"
        unless defined $nft;

    print STDERR "[INFO] nft: $nft\n"
        if $OPT{verbose};

    my $stderr_fh = gensym();

    my ($stdin_fh, $stdout_fh);

    my $pid;

    eval {
        $pid = open3(
            $stdin_fh,
            $stdout_fh,
            $stderr_fh,
            $nft,
            '-j',
            'list',
            'ruleset',
        );
    };

    if ($@) {
        die "ERROR: unable to execute nft: $@\n";
    }

    close($stdin_fh);

    my $selector = IO::Select->new();

    $selector->add($stdout_fh);
    $selector->add($stderr_fh);

    my $stdout = '';
    my $stderr = '';

    while ($selector->count) {

        my @ready = $selector->can_read(1);

        for my $fh (@ready) {

            my $buffer = '';

            my $bytes = sysread(
                $fh,
                $buffer,
                65536,
            );

            if (!defined $bytes || $bytes == 0) {
                $selector->remove($fh);
                close($fh);
                next;
            }

            my $fd = fileno($fh);

            if (defined($fd) && defined(fileno($stdout_fh))
                && $fd == fileno($stdout_fh)) {

                $stdout .= $buffer;

            } else {

                $stderr .= $buffer;
            }
        }
    }

    waitpid($pid, 0);

    my $exit_code = $? >> 8;
    my $signal    = $? & 127;

    if ($signal) {
        die sprintf(
            "ERROR: nft terminated by signal %d.\n%s",
            $signal,
            length($stderr) ? "nft stderr: $stderr\n" : ''
        );
    }

    if ($exit_code != 0) {

        $stderr = trim($stderr);

        die "ERROR: nft failed with exit code $exit_code.\n"
            . (length($stderr) ? "nft: $stderr\n" : '');
    }

    if (!length(trim($stdout))) {

        die "ERROR: nft returned empty JSON output.\n"
            . (length(trim($stderr)) ? "nft: $stderr\n" : '');
    }

    my $data;

    eval {
        $data = decode_json($stdout);
    };

    if ($@) {
        my $error = $@;
        $error =~ s/\s+$//;

        die "ERROR: unable to parse nft JSON: $error\n";
    }

    unless (is_hash($data)) {
        die "ERROR: nft returned unexpected JSON structure.\n";
    }

    unless (is_array($data->{nftables})) {
        die "ERROR: nft JSON does not contain a valid 'nftables' array.\n";
    }

    return $data;
}

# ============================================================
# nft JSON rendering
# ============================================================

sub render_value {

    my ($value) = @_;

    return '' unless defined $value;

    if (!ref($value)) {
        return "$value";
    }

    if (is_array($value)) {

        my @items;

        for my $item (@{$value}) {
            push @items, render_value($item);
        }

        return join(', ', @items);
    }

    if (is_hash($value)) {

        my @parts;

        for my $key (sort keys %{$value}) {

            my $v = $value->{$key};

            next if ref($v) && !is_array($v) && !is_hash($v);

            push @parts,
                "$key=" . render_value($v);
        }

        return '{' . join(', ', @parts) . '}';
    }

    return '';
}

sub render_operand {

    my ($value) = @_;

    return '' unless defined $value;

    if (!ref($value)) {
        return "$value";
    }

    if (is_array($value)) {
        return join(', ', map { render_operand($_) } @{$value});
    }

    if (is_hash($value)) {

        if (exists $value->{prefix}) {
            return safe_string($value->{prefix});
        }

        if (exists $value->{prefixes}
            && is_array($value->{prefixes})) {

            return join(', ', @{$value->{prefixes}});
        }

        if (exists $value->{range}) {
            return render_operand($value->{range});
        }

        return render_value($value);
    }

    return '';
}

sub render_match {

    my ($key, $value) = @_;

    $key = safe_string($key);

    return $key
        unless defined $value;

    if (!ref($value)) {
        return "$key $value";
    }

    if (is_array($value)) {
        return "$key " . render_operand($value);
    }

    if (is_hash($value)) {

        my @parts;

        for my $k (sort keys %{$value}) {
            push @parts,
                "$k " . render_operand($value->{$k});
        }

        return "$key " . join(' ', @parts);
    }

    return $key;
}

sub render_expr {

    my ($expr) = @_;

    return '' unless is_hash($expr);

    my @parts;

    for my $key (sort keys %{$expr}) {

        my $value = $expr->{$key};

        if ($key eq 'match'
            || $key eq 'payload'
            || $key eq 'cmp'
            || $key eq 'lookup'
            || $key eq 'ct'
            || $key eq 'meta'
            || $key eq 'counter'
            || $key eq 'limit'
            || $key eq 'log'
            || $key eq 'accept'
            || $key eq 'drop'
            || $key eq 'reject'
            || $key eq 'return'
            || $key eq 'queue'
            || $key eq 'dnat'
            || $key eq 'snat'
            || $key eq 'masquerade'
            || $key eq 'redirect') {

            push @parts, render_match($key, $value);

        } else {

            push @parts, render_match($key, $value);
        }
    }

    return join(' ', @parts);
}

sub render_rule {

    my ($rule) = @_;

    return '' unless is_hash($rule);

    my @parts;

    if (is_array($rule->{expr})) {

        for my $expr (@{$rule->{expr}}) {

            next unless is_hash($expr);

            my $text = render_expr($expr);

            push @parts, $text
                if length trim($text);
        }
    }

    return join(' ', @parts);
}

# ============================================================
# Recursive JSON traversal
# ============================================================

sub walk_node {

    my ($node, $callback) = @_;

    return unless defined $node;
    return unless ref($callback) eq 'CODE';

    $callback->($node);

    if (is_array($node)) {

        for my $item (@{$node}) {
            walk_node($item, $callback);
        }

    } elsif (is_hash($node)) {

        for my $key (keys %{$node}) {

            my $value = $node->{$key};

            next unless ref($value);

            walk_node($value, $callback);
        }
    }
}

# ============================================================
# Extract port
# ============================================================

sub extract_port {

    my ($value) = @_;

    return unless defined $value;

    if (!ref($value)) {

        my $text = safe_string($value);

        if ($text =~ /^(\d+)$/) {
            return $1;
        }

        if ($text =~ /^(\d+)-(\d+)$/) {
            return "$1-$2";
        }

        return;
    }

    if (is_hash($value)) {

        if (exists $value->{port}) {
            return extract_port($value->{port});
        }

        if (exists $value->{ports}) {
            return extract_port($value->{ports});
        }

        if (exists $value->{range}) {
            return extract_port($value->{range});
        }

        if (exists $value->{start} && exists $value->{end}) {

            my $start = safe_string($value->{start});
            my $end   = safe_string($value->{end});

            return "$start-$end";
        }
    }

    if (is_array($value)) {

        my @ports;

        for my $item (@{$value}) {

            my $port = extract_port($item);

            push @ports, $port
                if defined $port && length $port;
        }

        return join(',', @ports)
            if @ports;
    }

    return;
}

# ============================================================
# Extract address
# ============================================================

sub extract_address {

    my ($value) = @_;

    return unless defined $value;

    if (!ref($value)) {
        return safe_string($value);
    }

    if (is_array($value)) {

        my @addresses;

        for my $item (@{$value}) {

            my $address = extract_address($item);

            push @addresses, $address
                if defined $address && length $address;
        }

        return join(',', @addresses)
            if @addresses;

        return;
    }

    if (is_hash($value)) {

        for my $key (
            qw(
                addr
                address
                prefix
                prefixlen
                ip
                ipv4_addr
                ipv6_addr
            )
        ) {

            if (exists $value->{$key}) {

                my $result =
                    extract_address($value->{$key});

                return $result
                    if defined $result && length $result;
            }
        }
    }

    return;
}

# ============================================================
# Parse one nft rule
# ============================================================

sub parse_rule {

    my ($rule, $family, $table, $chain, $hook) = @_;

    return unless is_hash($rule);

    my %parsed = (

        family        => safe_string($family),
        table         => safe_string($table),
        chain         => safe_string($chain),
        hook          => safe_string($hook),

        handle        => safe_string($rule->{handle}),
        comment       => '',
        text          => '',

        verdict       => '',
        packets       => 0,
        bytes         => 0,

        protocols     => [],
        tcp_ports     => [],
        udp_ports     => [],

        source        => [],
        destination   => [],

        interfaces_in => [],
        interfaces_out => [],

        ct_states     => [],

        ipv4          => 0,
        ipv6          => 0,

        log           => 0,
        nat           => 0,
        queue         => 0,

        restricted    => 0,
    );

    if (exists $rule->{comment}
        && !ref($rule->{comment})) {

        $parsed{comment} =
            safe_string($rule->{comment});
    }

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    if (is_hash($rule->{counter})) {

        $parsed{packets} =
            safe_number($rule->{counter}->{packets});

        $parsed{bytes} =
            safe_number($rule->{counter}->{bytes});
    }

    # --------------------------------------------------------
    # Expressions
    # --------------------------------------------------------

    if (is_array($rule->{expr})) {

        for my $expr (@{$rule->{expr}}) {

            next unless is_hash($expr);

            # -----------------------------
            # verdicts
            # -----------------------------

            if (exists $expr->{accept}) {
                $parsed{verdict} = 'accept';
            }

            if (exists $expr->{drop}) {
                $parsed{verdict} = 'drop';
            }

            if (exists $expr->{reject}) {
                $parsed{verdict} = 'reject';
            }

            if (exists $expr->{return}) {
                $parsed{verdict} = 'return';
            }

            if (exists $expr->{queue}) {
                $parsed{verdict} = 'queue';
                $parsed{queue} = 1;
            }

            # -----------------------------
            # log
            # -----------------------------

            if (exists $expr->{log}) {
                $parsed{log} = 1;
            }

            # -----------------------------
            # NAT
            # -----------------------------

            if (exists $expr->{dnat}) {
                $parsed{nat} = 1;
            }

            if (exists $expr->{snat}) {
                $parsed{nat} = 1;
            }

            if (exists $expr->{masquerade}) {
                $parsed{nat} = 1;
            }

            if (exists $expr->{redirect}) {
                $parsed{nat} = 1;
            }

            # -----------------------------
            # conntrack
            # -----------------------------

            if (is_hash($expr->{ct})) {

                my $ct = $expr->{ct};

                if (exists $ct->{state}) {

                    my $states = $ct->{state};

                    if (is_array($states)) {

                        for my $state (@{$states}) {

                            next if ref($state);

                            add_unique(
                                $parsed{ct_states},
                                uc($state),
                            );
                        }

                    } elsif (!ref($states)) {

                        add_unique(
                            $parsed{ct_states},
                            uc($states),
                        );
                    }
                }
            }

            # -----------------------------
            # payload
            # -----------------------------

            if (is_hash($expr->{payload})) {

                my $payload =
                    $expr->{payload};

                my $protocol =
                    safe_string($payload->{protocol});

                if (length $protocol) {

                    $protocol =
                        lc($protocol);

                    add_unique(
                        $parsed{protocols},
                        $protocol,
                    );

                    if ($protocol eq 'ip') {
                        $parsed{ipv4} = 1;
                    }

                    if ($protocol eq 'ip6') {
                        $parsed{ipv6} = 1;
                    }
                }

                my $field =
                    safe_string($payload->{field});

                if ($field eq 'protocol') {

                    # Protocol itself is handled below
                    # through match expressions.
                }
            }

            # -----------------------------
            # interface
            # -----------------------------

            for my $key (
                qw(iifname oifname iif oif)
            ) {

                next unless exists $expr->{$key};

                my $value =
                    $expr->{$key};

                if (is_array($value)) {

                    for my $iface (@{$value}) {

                        next if ref($iface);

                        if ($key eq 'iifname'
                            || $key eq 'iif') {

                            add_unique(
                                $parsed{interfaces_in},
                                $iface,
                            );

                        } else {

                            add_unique(
                                $parsed{interfaces_out},
                                $iface,
                            );
                        }
                    }

                } elsif (!ref($value)) {

                    if ($key eq 'iifname'
                        || $key eq 'iif') {

                        add_unique(
                            $parsed{interfaces_in},
                            $value,
                        );

                    } else {

                        add_unique(
                            $parsed{interfaces_out},
                            $value,
                        );
                    }
                }
            }

            # -----------------------------
            # Match
            # -----------------------------

            if (is_hash($expr->{match})) {

                my $match =
                    $expr->{match};

                my $op =
                    safe_string($match->{op});

                my $left =
                    $match->{left};

                my $right =
                    $match->{right};

                # Protocol matching
                if (is_hash($left)
                    && exists $left->{payload}
                    && is_hash($left->{payload})) {

                    my $payload =
                        $left->{payload};

                    my $field =
                        safe_string($payload->{field});

                    if ($field eq 'protocol') {

                        my $protocol =
                            extract_address($right);

                        $protocol =
                            lc($protocol // '');

                        add_unique(
                            $parsed{protocols},
                            $protocol,
                        );

                        if ($protocol eq 'tcp') {
                            $parsed{tcp_match} = 1;
                        }

                        if ($protocol eq 'udp') {
                            $parsed{udp_match} = 1;
                        }

                        if ($protocol eq 'icmp'
                            || $protocol eq 'icmpv4') {

                            $parsed{icmp_match} = 1;
                        }

                        if ($protocol eq 'icmpv6') {
                            $parsed{icmpv6_match} = 1;
                        }
                    }
                }

                # TCP / UDP ports
                if (is_hash($left)
                    && exists $left->{payload}
                    && is_hash($left->{payload})) {

                    my $payload =
                        $left->{payload};

                    my $field =
                        safe_string($payload->{field});

                    my $protocol =
                        safe_string($payload->{protocol});

                    if ($field eq 'sport'
                        || $field eq 'dport') {

                        my $port =
                            extract_port($right);

                        if (defined $port
                            && length $port) {

                            if (lc($protocol) eq 'tcp') {

                                add_unique(
                                    $parsed{tcp_ports},
                                    $port,
                                );

                            } elsif (lc($protocol) eq 'udp') {

                                add_unique(
                                    $parsed{udp_ports},
                                    $port,
                                );
                            }
                        }
                    }
                }

                # IPv4 addresses
                if (is_hash($left)
                    && exists $left->{payload}
                    && is_hash($left->{payload})) {

                    my $payload =
                        $left->{payload};

                    my $protocol =
                        safe_string($payload->{protocol});

                    my $field =
                        safe_string($payload->{field});

                    if ($protocol eq 'ip') {

                        $parsed{ipv4} = 1;

                        if ($field eq 'saddr') {

                            my $addr =
                                extract_address($right);

                            add_unique(
                                $parsed{source},
                                $addr,
                            ) if defined $addr;

                        } elsif ($field eq 'daddr') {

                            my $addr =
                                extract_address($right);

                            add_unique(
                                $parsed{destination},
                                $addr,
                            ) if defined $addr;
                        }
                    }

                    if ($protocol eq 'ip6') {

                        $parsed{ipv6} = 1;

                        if ($field eq 'saddr') {

                            my $addr =
                                extract_address($right);

                            add_unique(
                                $parsed{source},
                                $addr,
                            ) if defined $addr;

                        } elsif ($field eq 'daddr') {

                            my $addr =
                                extract_address($right);

                            add_unique(
                                $parsed{destination},
                                $addr,
                            ) if defined $addr;
                        }
                    }
                }
            }

            # -----------------------------
            # meta protocol
            # -----------------------------

            if (is_hash($expr->{meta})) {

                my $meta =
                    $expr->{meta};

                my $key =
                    safe_string($meta->{key});

                if ($key eq 'protocol') {

                    my $value =
                        safe_string($meta->{value});

                    add_unique(
                        $parsed{protocols},
                        lc($value),
                    ) if length $value;
                }
            }
        }
    }

    # --------------------------------------------------------
    # Restricted ports
    # --------------------------------------------------------

    my %restricted_ports = map {
        $_ => 1
    } qw(
        21
        23
        25
        110
        135
        139
        143
        445
        3389
        5900
    );

    for my $port (
        @{$parsed{tcp_ports}},
        @{$parsed{udp_ports}}
    ) {

        my $base = $port;

        if ($base =~ /^(\d+)-/) {
            $base = $1;
        }

        if ($restricted_ports{$base}) {
            $parsed{restricted} = 1;
        }
    }

    # --------------------------------------------------------
    # Render rule
    # --------------------------------------------------------

    $parsed{text} = render_rule($rule);

    $parsed{text} = '(empty rule)'
        unless length trim($parsed{text});

    return \%parsed;
}

# ============================================================
# Analyze complete nftables JSON
# ============================================================

sub analyze {

    my ($data) = @_;

    die "ERROR: invalid nftables data.\n"
        unless is_hash($data);

    my $objects = $data->{nftables};

    die "ERROR: nftables object is not an array.\n"
        unless is_array($objects);

    @RULES = ();
    @CHAINS = ();
    @TABLES = ();
    @FINDINGS = ();
    @SERVICES = ();

    %TABLE_LOOKUP = ();
    %CHAIN_LOOKUP = ();
    %DUPLICATES = ();

    %COUNTERS = (
        rules             => 0,
        accept            => 0,
        drop              => 0,
        reject            => 0,
        return            => 0,
        queue             => 0,
        log               => 0,
        nat               => 0,
        masquerade        => 0,
        redirect          => 0,
        dnat              => 0,
        snat              => 0,
        established       => 0,
        related           => 0,
        invalid           => 0,
        tcp               => 0,
        udp               => 0,
        icmp              => 0,
        icmpv6            => 0,
        ipv4              => 0,
        ipv6              => 0,
        interfaces        => 0,
        source_ports      => 0,
        destination_ports => 0,
    );

    # --------------------------------------------------------
    # First pass: tables
    # --------------------------------------------------------

    for my $obj (@{$objects}) {

        next unless is_hash($obj);

        next unless exists $obj->{table};
        next unless is_hash($obj->{table});

        my $table = $obj->{table};

        my $family =
            safe_string($table->{family});

        my $name =
            safe_string($table->{name});

        next unless length $name;

        my $key =
            "$family:$name";

        $TABLE_LOOKUP{$key} = 1;

        push @TABLES, {
            family => $family,
            name   => $name,
        };
    }

    # --------------------------------------------------------
    # Second pass: chains
    # --------------------------------------------------------

    for my $obj (@{$objects}) {

        next unless is_hash($obj);

        next unless exists $obj->{chain};
        next unless is_hash($obj->{chain});

        my $chain = $obj->{chain};

        my $family =
            safe_string($chain->{family});

        my $table =
            safe_string($chain->{table});

        my $name =
            safe_string($chain->{name});

        next unless length $name;

        my $hook =
            safe_string($chain->{hook});

        my $type =
            safe_string($chain->{type});

        my $policy =
            safe_string($chain->{policy});

        my $key =
            "$family:$table:$name";

        my %chain_info = (
            family => $family,
            table  => $table,
            name   => $name,
            hook   => $hook,
            type   => $type,
            policy => $policy,
        );

        $CHAIN_LOOKUP{$key} = \%chain_info;

        push @CHAINS, \%chain_info;
    }

    # --------------------------------------------------------
    # Third pass: rules
    # --------------------------------------------------------

    for my $obj (@{$objects}) {

        next unless is_hash($obj);

        next unless exists $obj->{rule};
        next unless is_hash($obj->{rule});

        my $rule =
            $obj->{rule};

        my $family =
            safe_string($rule->{family});

        my $table =
            safe_string($rule->{table});

        my $chain =
            safe_string($rule->{chain});

        my $lookup_key =
            "$family:$table:$chain";

        my $chain_info =
            $CHAIN_LOOKUP{$lookup_key};

        my $hook = '';

        if (is_hash($chain_info)) {

            $hook =
                safe_string($chain_info->{hook});

            $hook = ''
                if ref($chain_info->{hook});
        }

        my $parsed =
            parse_rule(
                $rule,
                $family,
                $table,
                $chain,
                $hook,
            );

        next unless is_hash($parsed);

        push @RULES, $parsed;

        $COUNTERS{rules}++;

        my $verdict =
            safe_string($parsed->{verdict});

        if ($verdict eq 'accept') {
            $COUNTERS{accept}++;
        } elsif ($verdict eq 'drop') {
            $COUNTERS{drop}++;
        } elsif ($verdict eq 'reject') {
            $COUNTERS{reject}++;
        } elsif ($verdict eq 'return') {
            $COUNTERS{return}++;
        } elsif ($verdict eq 'queue') {
            $COUNTERS{queue}++;
        }

        $COUNTERS{log}++
            if safe_number($parsed->{log});

        $COUNTERS{nat}++
            if safe_number($parsed->{nat});

        if (safe_number($parsed->{ipv4})) {
            $COUNTERS{ipv4}++;
        }

        if (safe_number($parsed->{ipv6})) {
            $COUNTERS{ipv6}++;
        }

        if (is_array($parsed->{protocols})) {

            for my $protocol (
                @{$parsed->{protocols}}
            ) {

                $protocol =
                    lc(safe_string($protocol));

                $COUNTERS{tcp}++
                    if $protocol eq 'tcp';

                $COUNTERS{udp}++
                    if $protocol eq 'udp';

                $COUNTERS{icmp}++
                    if $protocol eq 'icmp';

                $COUNTERS{icmpv6}++
                    if $protocol eq 'icmpv6';
            }
        }

        if (is_array($parsed->{ct_states})) {

            for my $state (
                @{$parsed->{ct_states}}
            ) {

                $state =
                    uc(safe_string($state));

                $COUNTERS{established}++
                    if $state eq 'ESTABLISHED';

                $COUNTERS{related}++
                    if $state eq 'RELATED';

                $COUNTERS{invalid}++
                    if $state eq 'INVALID';
            }
        }

        if (is_array($parsed->{tcp_ports})) {
            $COUNTERS{source_ports} +=
                scalar @{$parsed->{tcp_ports}};
        }

        if (is_array($parsed->{udp_ports})) {
            $COUNTERS{destination_ports} +=
                scalar @{$parsed->{udp_ports}};
        }

        if (is_array($parsed->{interfaces_in})) {
            $COUNTERS{interfaces} +=
                scalar @{$parsed->{interfaces_in}};
        }

        if (is_array($parsed->{interfaces_out})) {
            $COUNTERS{interfaces} +=
                scalar @{$parsed->{interfaces_out}};
        }
    }

    analyze_policies();
    analyze_empty_chains();
    analyze_zero_hit_rules();
    analyze_duplicates();
    analyze_services();
    analyze_special_rules();
}

# ============================================================
# Findings
# ============================================================

sub finding {

    my ($severity, $title, $description) = @_;

    $severity    = safe_string($severity);
    $title       = safe_string($title);
    $description = safe_string($description);

    return unless length $title;

    push @FINDINGS, {
        severity    => $severity,
        title       => $title,
        description => $description,
    };
}

sub analyze_policies {

    my %input_policies;

    for my $chain (@CHAINS) {

        next unless is_hash($chain);

        my $hook =
            safe_string($chain->{hook});

        my $policy =
            lc(safe_string($chain->{policy}));

        my $name =
            safe_string($chain->{name});

        next unless $hook eq 'input';
        next unless length $name;

        $input_policies{$name} = $policy;
    }

    for my $name (keys %input_policies) {

        my $policy =
            $input_policies{$name};

        if ($policy eq 'accept') {

            finding(
                'HIGH',
                "INPUT chain has ACCEPT policy",
                "Input chain '$name' uses an ACCEPT default policy."
            );
        }
    }
}

sub analyze_empty_chains {

    for my $chain (@CHAINS) {

        next unless is_hash($chain);

        my $family =
            safe_string($chain->{family});

        my $table =
            safe_string($chain->{table});

        my $name =
            safe_string($chain->{name});

        my $count = 0;

        for my $rule (@RULES) {

            next unless is_hash($rule);

            if (
                safe_string($rule->{family}) eq $family
                &&
                safe_string($rule->{table}) eq $table
                &&
                safe_string($rule->{chain}) eq $name
            ) {
                $count++;
            }
        }

        if ($count == 0) {

            finding(
                'LOW',
                "Empty chain",
                "Chain '$family/$table/$name' contains no parsed rules."
            );
        }
    }
}

sub analyze_zero_hit_rules {

    my $zero = 0;

    for my $rule (@RULES) {

        next unless is_hash($rule);

        my $packets =
            safe_number($rule->{packets});

        $zero++
            if $packets == 0;
    }

    if ($zero > 0) {

        finding(
            'LOW',
            "Rules with zero packet hits",
            "$zero rule(s) currently have zero packet counters."
        );
    }
}

sub analyze_duplicates {

    for my $rule (@RULES) {

        next unless is_hash($rule);

        my $text =
            safe_string($rule->{text});

        next unless length $text;

        $DUPLICATES{$text}++;
    }

    my $duplicate_count = 0;

    for my $text (keys %DUPLICATES) {

        my $count =
            safe_number($DUPLICATES{$text});

        $duplicate_count++
            if $count > 1;
    }

    if ($duplicate_count > 0) {

        finding(
            'LOW',
            "Duplicate rule definitions",
            "$duplicate_count duplicate rule definition(s) detected."
        );
    }
}

# ============================================================
# Service exposure analysis
# ============================================================

sub analyze_services {

    my %known_tcp = (

        20   => 'FTP-data',
        21   => 'FTP',
        22   => 'SSH',
        23   => 'Telnet',
        25   => 'SMTP',
        53   => 'DNS',
        80   => 'HTTP',
        110  => 'POP3',
        111  => 'rpcbind',
        135  => 'MS-RPC',
        139  => 'NetBIOS',
        143  => 'IMAP',
        443  => 'HTTPS',
        445  => 'SMB',
        587  => 'SMTP submission',
        993  => 'IMAPS',
        995  => 'POP3S',
        1433 => 'MSSQL',
        1521 => 'Oracle',
        3306 => 'MySQL',
        3389 => 'RDP',
        5432 => 'PostgreSQL',
        5900 => 'VNC',
        6379 => 'Redis',
        8080 => 'HTTP-alt',
        8443 => 'HTTPS-alt',
    );

    my %seen;

    for my $rule (@RULES) {

        next unless is_hash($rule);

        my $verdict =
            lc(safe_string($rule->{verdict}));

        next unless $verdict eq 'accept';

        my $hook =
            lc(safe_string($rule->{hook}));

        next unless $hook eq 'input'
            || $hook eq 'forward';

        my $restricted =
            safe_number($rule->{restricted});

        next if $restricted;

        if (is_array($rule->{tcp_ports})) {

            for my $port (
                @{$rule->{tcp_ports}}
            ) {

                my $port_text =
                    safe_string($port);

                next unless length $port_text;

                my $base = $port_text;

                if ($base =~ /^(\d+)/) {
                    $base = $1;
                }

                next unless $base =~ /^\d+$/;

                my $name =
                    $known_tcp{$base}
                    // 'Unknown TCP service';

                my $key =
                    "tcp:$base";

                next if $seen{$key}++;

                push @SERVICES, {
                    protocol => 'tcp',
                    port     => $base,
                    name     => $name,
                    chain    => safe_string($rule->{chain}),
                    table    => safe_string($rule->{table}),
                    hook     => $hook,
                    rule     => safe_string($rule->{text}),
                };
            }
        }
    }

    for my $service (@SERVICES) {

        next unless is_hash($service);

        my $port =
            safe_string($service->{port});

        my $name =
            safe_string($service->{name});

        my $severity = 'LOW';

        if ($port eq '23'
            || $port eq '135'
            || $port eq '139'
            || $port eq '445'
            || $port eq '3389'
            || $port eq '5900') {

            $severity = 'HIGH';

        } elsif (
            $port eq '21'
            || $port eq '25'
            || $port eq '110'
            || $port eq '143'
        ) {

            $severity = 'MEDIUM';
        }

        finding(
            $severity,
            "Exposed TCP service: $name",
            "TCP/$port is accepted by an inbound nftables rule."
        );
    }
}

# ============================================================
# Special rule analysis
# ============================================================

sub analyze_special_rules {

    my $has_invalid_drop = 0;
    my $has_established  = 0;
    my $has_related      = 0;

    for my $rule (@RULES) {

        next unless is_hash($rule);

        my $verdict =
            lc(safe_string($rule->{verdict}));

        my @states;

        if (is_array($rule->{ct_states})) {
            @states = @{$rule->{ct_states}};
        }

        for my $state (@states) {

            $state =
                uc(safe_string($state));

            if ($state eq 'INVALID'
                && $verdict eq 'drop') {

                $has_invalid_drop = 1;
            }

            if ($state eq 'ESTABLISHED') {
                $has_established = 1;
            }

            if ($state eq 'RELATED') {
                $has_related = 1;
            }
        }
    }

    unless ($has_invalid_drop) {

        finding(
            'MEDIUM',
            'No explicit INVALID drop detected',
            'The analyzer did not find an explicit conntrack INVALID drop rule.'
        );
    }

    unless ($has_established && $has_related) {

        finding(
            'MEDIUM',
            'Established/related handling incomplete',
            'The analyzer did not detect both ESTABLISHED and RELATED handling.'
        );
    }
}

# ============================================================
# Header
# ============================================================

sub print_header {

    print "\n";
    print "============================================================\n";
    print " KYGnus Firewall Check\n";
    print " Version : $VERSION\n";
    print " Mode    : READ-ONLY\n";
    print " Time    : ",
        strftime('%Y-%m-%d %H:%M:%S', localtime),
        "\n";
    print "============================================================\n\n";
}

# ============================================================
# Summary
# ============================================================

sub print_summary {

    print "Firewall Summary\n";
    print "----------------\n";

    printf "Tables          : %d\n", scalar @TABLES;
    printf "Chains          : %d\n", scalar @CHAINS;
    printf "Rules           : %d\n", scalar @RULES;

    printf "ACCEPT rules    : %d\n",
        $COUNTERS{accept};

    printf "DROP rules      : %d\n",
        $COUNTERS{drop};

    printf "REJECT rules    : %d\n",
        $COUNTERS{reject};

    printf "LOG rules       : %d\n",
        $COUNTERS{log};

    printf "NAT rules       : %d\n",
        $COUNTERS{nat};

    printf "IPv4 rules      : %d\n",
        $COUNTERS{ipv4};

    printf "IPv6 rules      : %d\n",
        $COUNTERS{ipv6};

    printf "TCP matches     : %d\n",
        $COUNTERS{tcp};

    printf "UDP matches     : %d\n",
        $COUNTERS{udp};

    printf "ICMP matches    : %d\n",
        $COUNTERS{icmp};

    printf "ICMPv6 matches  : %d\n",
        $COUNTERS{icmpv6};

    print "\n";
}

# ============================================================
# Chains
# ============================================================

sub print_chains {

    print "Chains\n";
    print "------\n";

    for my $chain (@CHAINS) {

        next unless is_hash($chain);

        printf "%-18s %-18s %-12s policy=%s\n",
            safe_string($chain->{family}),
            safe_string($chain->{table}),
            safe_string($chain->{name}),
            safe_string($chain->{policy});
    }

    print "\n";
}

# ============================================================
# Services
# ============================================================

sub print_services {

    print "Exposed Services\n";
    print "----------------\n";

    if (!@SERVICES) {

        print "No known TCP services detected.\n\n";
        return;
    }

    for my $service (@SERVICES) {

        next unless is_hash($service);

        printf "%-6s/%-5s %-20s chain=%s\n",
            safe_string($service->{protocol}),
            safe_string($service->{port}),
            safe_string($service->{name}),
            safe_string($service->{chain});
    }

    print "\n";
}

# ============================================================
# Findings
# ============================================================

sub print_findings {

    print "Security Findings\n";
    print "-----------------\n";

    if (!@FINDINGS) {

        print "No findings generated.\n\n";
        return;
    }

    my @sorted =
        sort {
            severity_rank(
                safe_string($b->{severity})
            )
            <=>
            severity_rank(
                safe_string($a->{severity})
            )
        } @FINDINGS;

    for my $item (@sorted) {

        next unless is_hash($item);

        printf "[%-8s] %s\n",
            safe_string($item->{severity}),
            safe_string($item->{title});

        printf "           %s\n",
            safe_string($item->{description});
    }

    print "\n";
}

# ============================================================
# Rules
# ============================================================

sub print_rules {

    print "Parsed Rules\n";
    print "------------\n";

    my $index = 0;

    for my $rule (@RULES) {

        next unless is_hash($rule);

        $index++;

        printf "%5d  %-8s %-10s %-16s %-18s\n",
            $index,
            safe_string($rule->{verdict}),
            safe_string($rule->{family}),
            safe_string($rule->{table}),
            safe_string($rule->{chain});

        printf "       %s\n",
            safe_string($rule->{text});
    }

    print "\n";
}

# ============================================================
# JSON output
# ============================================================

sub json_report {

    my %report = (

        version => $VERSION,

        generated =>
            strftime(
                '%Y-%m-%dT%H:%M:%S%z',
                localtime
            ),

        summary => {
            tables  => scalar @TABLES,
            chains  => scalar @CHAINS,
            rules   => scalar @RULES,
            counters => \%COUNTERS,
        },

        tables    => \@TABLES,
        chains    => \@CHAINS,
        rules     => \@RULES,
        services  => \@SERVICES,
        findings  => \@FINDINGS,
    );

    print encode_json(\%report), "\n";
}

# ============================================================
# Main
# ============================================================

eval {

    check_privileges();

    my $data = run_nft();

    analyze($data);

    if ($OPT{json}) {

        json_report();
        exit 0;
    }

    print_header();

    if (
        !$OPT{summary}
        && !$OPT{services}
        && !$OPT{findings}
        && !$OPT{rules}
    ) {

        print_summary();
        print_chains();
        print_services();
        print_findings();

    } else {

        print_summary()
            if $OPT{summary};

        print_services()
            if $OPT{services};

        print_findings()
            if $OPT{findings};

        print_rules()
            if $OPT{rules};
    }

    if ($OPT{verbose}) {

        print "Verbose diagnostics\n";
        print "-------------------\n";

        printf "nftables objects : %d\n",
            scalar @{$data->{nftables}};

        printf "Parsed tables    : %d\n",
            scalar @TABLES;

        printf "Parsed chains    : %d\n",
            scalar @CHAINS;

        printf "Parsed rules     : %d\n",
            scalar @RULES;

        printf "Findings         : %d\n",
            scalar @FINDINGS;

        printf "Services         : %d\n",
            scalar @SERVICES;

        print "\n";
    }

};

if ($@) {

    my $error = $@;

    $error =~ s/\s+$//;

    print STDERR "\n$error\n";

    exit 1;
}

exit 0;