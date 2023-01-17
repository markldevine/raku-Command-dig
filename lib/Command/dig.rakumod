unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

has         @.dns-servers   is rw   = [];
has         @.dns-domains   is rw   = [];

class Resolution {
    has         $.ip-address        is rw;
    has         %.alias-names       is rw;
    has         $.canonical-name    is rw;
    has         @.pointer-names     is rw;
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

#   HHHHHHHHHH.wwwww.com.   0       IN      CNAME   kkkkkkkkkk.wwwww.com.
#   kkkkkkkkkk.wwwww.com.   0       IN      A       11.11.111.11

grammar DIG-FORWARD {
    token TOP                   { ^ <records>+ }
    token records               { <address-record> || <canonical-name-record> }
    token address-record        { ^^ <canonical-name> '.' \s+ \d+ \s+ 'IN' \s+ 'A' \s+ <ip-address> $$ \n }
    token canonical-name-record { <alias-name> '.' \s+ \d+ \s+ 'IN' \s+ 'CNAME' \s+ <canonical-name> '.' $$ \n }
    token ip-address            { \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 }
    token alias-name            { [ \w || '-' || '.' <!before \s> ]+ }
    token canonical-name        { [ \w || '-' || '.' <!before \s> ]+ }
}

method resolve (Str:D $label-or-ipv4) {
    my Resolution $resolution .= new;
    if $label-or-ipv4 ~~ / ^ \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 $ / {
        $resolution.ip-address = $label-or-ipv4;
        my $retval = self!lookup-reverse($label-or-ipv4, :$resolution);
        return Nil unless $retval;
        for $resolution.pointer-names -> $pointer-name {
            self!lookup-forward($pointer-name, :$resolution);
        }
        return $resolution;
    }
    elsif $label-or-ipv4 ~~ / ^ ( \w || '-' || '.' <!before \s> )+ $ / {
        my $retval = self!lookup-forward($label-or-ipv4, :$resolution);
        return Nil unless $retval;
        self!lookup-reverse($resolution.ip-address, :$resolution);
        if $resolution.pointer-names.elems {
            my %h = $resolution.alias-names;
            for $resolution.pointer-names -> $pointer-name {
                next if $pointer-name eq $resolution.canonical-name;
                %h{$pointer-name} = 0;
            }
            $resolution.alias-names = %h;
        }
        return $retval;
    }
    else {
        fail "Cannot reconcile if <$label-or-ipv4> is a name/label or an IP address";
    }
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
    my @alias-names = [];
    my $canonical-name;
    my $ip-address;
    for $match<records> -> $record {
        if $record<address-record>:exists {
            $ip-address = $record<address-record><ip-address>.Str;
            my $c-name  = $record<address-record><canonical-name>.Str;
            if $canonical-name && $c-name ne $canonical-name {
                warn 'Multiple canonical names exist! STORED: <'
                     ~ $canonical-name
                     ~ '>  NEW: <'
                     ~ $c-name
                     ~ '>';
            }
            else {
                $canonical-name = $c-name;
            }
        }
        elsif $record<canonical-name-record>:exists {
            my $c-name  = $record<canonical-name-record><canonical-name>.Str;
            if $canonical-name && $c-name ne $canonical-name {
                warn 'Multiple canonical names exist! STORED: <'
                     ~ $canonical-name
                     ~ '>  NEW: <'
                     ~ $c-name
                     ~ '>';
            }
            else {
                $canonical-name = $c-name;
            }
            @alias-names.push: $record<canonical-name-record><alias-name>.Str;
        }
        else {
            die 'Should never happen...';
        }
    }
    return Nil unless $ip-address && $canonical-name;
    my %h = $resolution.alias-names;
    for @alias-names -> $alias-name {
        next if %h{$alias-name}:exists;
        %h{$alias-name}         = 0;
        $resolution.alias-names = %h;
    }
    if $resolution.canonical-name {
        if $canonical-name && $resolution.canonical-name ne $canonical-name {
            warn 'Multiple canonical names exist! STORED: <'
                 ~ $resolution.canonical-name
                 ~ '>  NEW: <'
                 ~ $canonical-name
                 ~ '>';
        }
    }
    else {
        $resolution.canonical-name      = $canonical-name;
    }
    $resolution.ip-address              = $ip-address;
    return($resolution);
}

#   222.2.222.222.in-addr.arpa. 259200 IN   PTR     nnnnnn.wwwww.com.
#   222.2.222.222.in-addr.arpa. 259200 IN   PTR     pppppppppp.wwwww.com.

grammar DIG-REVERSE {
    token TOP               { ^ <pointer-records>+ $ }
    token pointer-records   { ^^ <in-addr-arpa> \s+ \d+ \s+ 'IN' \s+ 'PTR' \s+ <name> '.' $$ \n }
    token in-addr-arpa      { $<octet-4> = \d ** 1..3 '.' $<octet-3> = \d ** 1..3 '.' $<octet-2> = \d ** 1..3 '.' $<octet-1> = \d ** 1..3 '.in-addr.arpa.' }
    token name              { ( \w || '-' || '.' <!before \s> )+ }
}

method !lookup-reverse (Str:D $ip-address!, :$resolution) {
    if @.dns-servers.elems {
        for @.dns-servers -> $dns-server {
            my @cmd     =   flat @base-cmd,
                            '@' ~ $dns-server,
                            '-x',
                            $ip-address,
                            'IN';
            my $proc    =   run @cmd, :out, :err;
            my $out     =   $proc.out.slurp(:close);
            my $err     =   $proc.err.slurp(:close);
            my $resobj  =   self!analyze-reverse(DIG-REVERSE.parse($out), :$resolution);
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
    my $resobj  =   self!analyze-reverse(DIG-REVERSE.parse($out), :$resolution);
    return $resobj with $resobj;
    return Nil;
}

method !analyze-reverse ($match, :$resolution) {
    return Nil unless $match ~~ Match;
    my @names = [];
    for $match<pointer-records> -> $pointer-record {
        @names.push: $pointer-record<name>.Str;
    }
    return Nil unless @names.elems;
    $resolution.pointer-names = @names;
    return $resolution;
}

=finish
