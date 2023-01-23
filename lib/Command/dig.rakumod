unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

submethod TWEAK {
    die "Install 'bind-utils' (or your OSes method) to provide 'dig' utility."
        unless "/usr/bin/dig".IO.x || "/bin/dig".IO.x;
}

has         @.dns-servers   is rw   = [];
has         @.dns-domains   is rw   = [];

class Resolution {
    has         %.ip-addresses;
    has         @.alias-names-chronological;
    has         %.alias-names;
    has         $.canonical-name;
    has         %.pointer-names;

    method merge-canonical-name (Str:D $new-canonical-name) {
        if $!canonical-name {
            if $new-canonical-name && $!canonical-name ne $new-canonical-name {
                $*ERR.put:  'Multiple canonical names exist! STORED: <'
                            ~ $!canonical-name
                            ~ '>  NEW: <'
                            ~ $new-canonical-name
                            ~ '>';
                die;
            }
        }
        else {
            $!canonical-name    = $new-canonical-name;
        }
    }

    method merge-ip-addresses (@new-ip-addresses) {
        for @new-ip-addresses -> $new-ip-address {
            if %!ip-addresses{$new-ip-address}:exists {
                warn 'New IP address <' ~ $new-ip-address ~ '> already encountered. Code to reconcile NYI...'
            }
            else {
                %!ip-addresses{$new-ip-address} = '';
            }
        }
    }

    method merge-alias-names (%new-alias-names, @alias-names) {
        if @alias-names.elems {
            if @!alias-names-chronological.elems {
                $*ERR.put: 'Attempting to update alias-names-chronological again...';
            }
            else {
                @!alias-names-chronological = @alias-names;
            }
        }

        for %new-alias-names.keys -> $new-alias-name {
            if %!alias-names{$new-alias-name}:exists && %new-alias-names{$new-alias-name} ne %!alias-names{$new-alias-name} {
                die 'Alias <' ~ $new-alias-name ~ '> --> <' ~ %new-alias-names{$new-alias-name} ~ '> previously recorded as <' ~ %!alias-names{$new-alias-name} ~ '>';
            }
            else {
                %!alias-names{$new-alias-name} = %new-alias-names{$new-alias-name};
            }
        }
    }

    method merge-pointer-names (Str:D $ip-address, @new-pointer-names) {
        for @new-pointer-names -> $new-pointer-name {
            if %!pointer-names{$new-pointer-name}:exists {
                warn 'New PTR name <' ~ $new-pointer-name ~ '> already encountered. This practice is legal but discouraged...'
            }
            else {
                %!pointer-names{$new-pointer-name} = $ip-address;
            }
        }
    }

    method supplement-records {
        for %!pointer-names.kv -> $name, $ip-addr {
            if %!ip-addresses{$ip-addr}:exists {
                %!ip-addresses{$ip-addr} = $name unless %!ip-addresses{$ip-addr}.chars;
            }
        }
    }

}

constant    @base-cmd       =       '/usr/bin/dig',
                                    '-4',
                                    '+nocomments',
                                    '+nocmd',
                                    '+nostats',
                                    '+noedns',
                                    '+nocookie',
                                    '+noquestion',
                                    '+noauthority',
                                    '+noadditional';

method resolve (Str:D $label-or-ipv4) {
    my Resolution $resolution .= new;
    if $label-or-ipv4 ~~ / ^ \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 $ / {
        my $retval = self!lookup-reverse($label-or-ipv4, :$resolution);
        return Nil unless $retval;
        for $resolution.pointer-names.keys -> $pointer-name {
            self!lookup-forward($pointer-name, :$resolution);
        }
        return $resolution;
    }
    elsif $label-or-ipv4 ~~ / ^ ( \w || '-' || '.' <!before \s> )+ $ / {
        my $retval = self!lookup-forward($label-or-ipv4, :$resolution);
        return Nil unless $retval;
        for $resolution.ip-addresses.keys -> $ip-address {
            self!lookup-reverse($ip-address, :$resolution);
        }
        return $retval;
    }
    else {
        fail "Cannot reconcile if <$label-or-ipv4> is a name/label or an IP address";
    }
}

grammar DIG-FORWARD {
    token TOP                   { ^ <records>+ }
    token records               { <address-record> || <canonical-name-record> }
    token address-record        { ^^ <canonical-name> '.' \s+ \d+ \s+ 'IN' \s+ 'A' \s+ <ip-address> $$ \n }
    token canonical-name-record { <alias-name> '.' \s+ \d+ \s+ 'IN' \s+ 'CNAME' \s+ <canonical-name> '.' $$ \n }
    token ip-address            { \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 }
    token alias-name            { [ \w || '-' || '.' <!before \s> ]+ }
    token canonical-name        { [ \w || '-' || '.' <!before \s> ]+ }
}

method !lookup-forward (Str:D $ip-label!, :$resolution) {
    for @.dns-servers -> $dns-server {
        if @.dns-domains.elems {
            for @.dns-domains -> $dns-domain {
                my @cmd     =   flat @base-cmd,
                                '+domain=' ~ $dns-domain, 
                                '@' ~ $dns-server,
                                $ip-label,
                                'A';
                my $proc    =   run @cmd, :out, :err;
                my $out     =   $proc.out.slurp(:close);
                my $err     =   $proc.err.slurp(:close);
                my $resobj  =   self!analyze-forward(DIG-FORWARD.parse($out), :$resolution);
                return $resobj with $resobj;
            }
        }
        else {
            my @cmd     =   flat @base-cmd,
                            '@' ~ $dns-server,
                            $ip-label,
                            'A';
            my $proc    =   run @cmd, :out, :err;
            my $out     =   $proc.out.slurp(:close);
            my $err     =   $proc.err.slurp(:close);
            return self!analyze-forward(DIG-FORWARD.parse($out), :$resolution);
        }
    }
    if @.dns-domains.elems {
        for @.dns-domains -> $dns-domain {
            my @cmd     =   flat @base-cmd,
                            '+domain=' ~ $dns-domain, 
                            $ip-label,
                            'A';
            my $proc    =   run @cmd, :out, :err;
            my $out     =   $proc.out.slurp(:close);
            my $err     =   $proc.err.slurp(:close);
            my $resobj  =   self!analyze-forward(DIG-FORWARD.parse($out), :$resolution);
            return $resobj with $resobj;
        }
    }
    else {
        my @cmd     =   flat @base-cmd,
                        $ip-label,
                        'A';
        my $proc    =   run @cmd, :out, :err;
        my $out     =   $proc.out.slurp(:close);
        my $err     =   $proc.err.slurp(:close);
        return self!analyze-forward(DIG-FORWARD.parse($out), :$resolution);
    }
    return Nil;
}

method !analyze-forward ($match, :$resolution) {
    return Nil unless $match ~~ Match;
    my @alias-names;
    my %alias-names;
    my $canonical-name;
    my @ip-addresses    = [];
    for $match<records> -> $record {
        if $record<address-record>:exists {
            @ip-addresses.push: $record<address-record><ip-address>.Str;
            my $c-name  = $record<address-record><canonical-name>.Str;
            if $canonical-name && $c-name ne $canonical-name {
                die 'Multiple canonical names exist in A records! STORED: <' ~ $canonical-name ~ '>  NEW: <' ~ $c-name ~ '>';
            }
            else {
                $canonical-name = $c-name;
            }
        }
        elsif $record<canonical-name-record>:exists {
            @alias-names.push: $record<canonical-name-record><alias-name>.Str;
            %alias-names{$record<canonical-name-record><alias-name>.Str} = $record<canonical-name-record><canonical-name>.Str;
        }
        else {
            die 'Should never happen...';
        }
    }
    return Nil unless @ip-addresses.elems && $canonical-name;
    $resolution.merge-alias-names(%alias-names, @alias-names) if %alias-names.elems;
    $resolution.merge-canonical-name($canonical-name);
    $resolution.merge-ip-addresses(@ip-addresses);
    $resolution.supplement-records;
    return($resolution);
}

grammar DIG-REVERSE {
    token TOP               { ^ <pointer-records>+ $ }
    token pointer-records   { ^^ <in-addr-arpa> \s+ \d+ \s+ 'IN' \s+ 'PTR' \s+ <name> '.' $$ \n }
    token in-addr-arpa      { \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.in-addr.arpa.' }
    token name              { ( \w || '-' || '.' <!before \s> )+ }
}

method !lookup-reverse (Str:D $ip-address!, Resolution:D :$resolution) {
    if @.dns-servers.elems {
        for @.dns-servers -> $dns-server {
            my @cmd     =   flat @base-cmd,
                            '@' ~ $dns-server,
                            '-x',
                            $ip-address,
                            'PTR';
            my $proc    =   run @cmd, :out, :err;
            my $out     =   $proc.out.slurp(:close);
            my $err     =   $proc.err.slurp(:close);
            my $match   =   DIG-REVERSE.parse($out);
            return Nil  unless $match ~~ Match;
            my $resobj  =   self!analyze-reverse(:$match, :$ip-address, :$resolution);
            return $resobj with $resobj;
        }
    }
    my @cmd     =   flat @base-cmd,
                    '-x',
                    $ip-address,
                    'IN';
    my $proc    =   run @cmd, :out, :err;
    my $out     =   $proc.out.slurp(:close);
    my $err     =   $proc.err.slurp(:close);
    my $match   =   DIG-REVERSE.parse($out);
    return Nil  unless $match ~~ Match;
    return self!analyze-reverse(:$match, :$ip-address, :$resolution);
}

method !analyze-reverse (Match:D :$match, Str:D :$ip-address, Resolution:D :$resolution) {
    return Nil unless $match ~~ Match;
    my @names = [];
    for $match<pointer-records> -> $pointer-record {
        @names.push: $pointer-record<name>.Str;
    }
    return Nil unless @names.elems;
    $resolution.merge-pointer-names($ip-address, @names);
    $resolution.supplement-records;
    return $resolution;
}

=finish
