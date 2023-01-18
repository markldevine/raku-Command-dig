unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

submethod TWEAK {
    die "Install 'bind-utils' (or your OSes method) to provide 'dig' utility."
        unless "/usr/bin/dig".IO.x || "/bin/dig".IO.x;
}

has         @.dns-servers   is rw   = [];
has         @.dns-domains   is rw   = [];

class Resolution {
    has         %.ip-addresses      is rw;
    has         %.alias-names       is rw;
    has         $.canonical-name    is rw;
    has         %.pointer-names     is rw;

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
                %!ip-addresses{$new-ip-address} = 0;
            }
        }
    }

    method merge-alias-names (Hash:D %new-alias-names) {
        for %new-alias-names.keys -> $new-alias-name {
            if %!alias-names{$new-alias-name}:exists && %new-alias-names{$new-alias-name} ne %!alias-names{$new-alias-name} {
                die 'Alias <' ~ $new-alias-name ~ '> --> <' ~ %new-alias-names{$new-alias-name} ~ '> previously recorded as <' ~ %!alias-names{$new-alias-name} ~ '>';
            }
            else {
                %!alias-names{$new-alias-name} = %new-alias-names{$new-alias-name};
            }
        }
    }

    method merge-pointer-names (@new-pointer-names) {
        for @new-pointer-names -> $new-pointer-name {
            if %!pointer-names{$new-pointer-name}:exists {
                warn 'New PTR name <' ~ $new-pointer-name ~ '> already encountered. Code to reconcile NYI...'
            }
            else {
                %!pointer-names{$new-pointer-name} = 0;
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
dd $resolution; die;
        for $resolution.ip-addresses.keys -> $ip-address {
            self!lookup-reverse($resolution.ip-address, :$resolution);
        }

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

#dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 www.google.com A
#    www.google.com.         88      IN      A       142.251.163.105
#    www.google.com.         88      IN      A       142.251.163.147
#    www.google.com.         88      IN      A       142.251.163.106
#    www.google.com.         88      IN      A       142.251.163.99
#    www.google.com.         88      IN      A       142.251.163.104
#    www.google.com.         88      IN      A       142.251.163.103
#
#dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 -x 142.251.163.105 PTR
#    105.163.251.142.in-addr.arpa. 2811 IN   PTR     wv-in-f105.1e100.net.
#dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 wv-in-f105.1e100.net A
#    wv-in-f105.1e100.net.   3600    IN      A       142.251.163.105

#   for <address-records> -> lookup-reverse($address-record{$address}......  %%%%%%%

method !analyze-forward ($match, :$resolution) {
    return Nil unless $match ~~ Match;
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
            %alias-names{$record<canonical-name-record><alias-name>.Str} = $record<canonical-name-record><canonical-name>.Str;
        }
        else {
            die 'Should never happen...';
        }
    }
    return Nil unless @ip-addresses.elems && $canonical-name;
    $resolution.merge-alias-names(%alias-names) if %alias-names.elems;
    $resolution.merge-canonical-name($canonical-name);
    $resolution.merge-ip-addresses(@ip-addresses);
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

--- wwww.wmata.com

dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 www.wmata.com A
www.wmata.com.          259200  IN      CNAME   www.f5dns.wmata.com.
www.f5dns.wmata.com.    2       IN      A       10.12.115.168



--- www.google.com

dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 www.google.com A
    www.google.com.         88      IN      A       142.251.163.105
    www.google.com.         88      IN      A       142.251.163.147
    www.google.com.         88      IN      A       142.251.163.106
    www.google.com.         88      IN      A       142.251.163.99
    www.google.com.         88      IN      A       142.251.163.104
    www.google.com.         88      IN      A       142.251.163.103

dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 -x 142.251.163.105 PTR
    105.163.251.142.in-addr.arpa. 2811 IN   PTR     wv-in-f105.1e100.net.
dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 wv-in-f105.1e100.net A
    wv-in-f105.1e100.net.   3600    IN      A       142.251.163.105

dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 -x 142.251.163.147 PTR
    147.163.251.142.in-addr.arpa. 507 IN    PTR     wv-in-f147.1e100.net.
dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 wv-in-f147.1e100.net A
    wv-in-f147.1e100.net.   6       IN      A       142.251.163.147



-- www.ibm.com

dig -4 +nocomments +nocmd +nostats +noedns +nocookie +noquestion +noauthority +noadditional @10.10.43.40 www.ibm.com A
    www.ibm.com.                                2247    IN      CNAME   www.ibm.com.cs186.net.
    www.ibm.com.cs186.net.                      126     IN      CNAME   outer-global-dual.ibmcom-tls12.edgekey.net.
    outer-global-dual.ibmcom-tls12.edgekey.net. 2534    IN      CNAME   e7817.dscx.akamaiedge.net.
    e7817.dscx.akamaiedge.net.                  20      IN      A       104.104.75.37
