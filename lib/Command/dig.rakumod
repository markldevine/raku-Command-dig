unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

use Terminal::ANSIColor;
use Prettier::Table;
use Data::Dump::Tree;
#use Grammar::Debugger;
#use Grammar::Tracer;

has         @.dns-servers   is rw   = [];
has         @.dns-domains   is rw   = [];

class Resolution {
    has         $.ip-address        is rw;
    has         %.alias-names       is rw;
    has         $.canonical-name    is rw;
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

#   P520TSMJGB.wwwww.com.   0       IN      CNAME   jatsmprd03.wwwww.com.
#   jatsmprd03.wwwww.com.   0       IN      A       10.10.137.41

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
        return self!lookup-reverse($label-or-ipv4, :$resolution);
    }
    if $label-or-ipv4 ~~ / ^ ( \w || '-' || '.' <!before \s> )+ $ / {
        return self!lookup-forward($label-or-ipv4, :$resolution);
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
        my $resobj  =   self!analyze-forward(DIG-FORWARD.parse($out), :$resolution);
        return $resobj with $resobj;
    }
    return Nil;
}

method !analyze-forward ($match) {
    return Nil unless $match ~~ Match;
    my %alias-names;
    my $canonical-name;
    my $ip-address;
    for $match<records> -> $record {
        if $record<address-record>:exists {
            $ip-address = $record<address-record><ip-address>.Str;
            $canonical-name = $record<address-record><canonical-name>.Str;
        }
        elsif $record<canonical-name-record>:exists {
            $canonical-name = $record<canonical-name-record><canonical-name>.Str;
            %alias-names{$record<canonical-name-record><alias-name>.Str} = $canonical-name;
        }
        else {
            die 'Should never happen...';
        }
    }
    return Nil unless $ip-address && $canonical-name;
    return Resolution.new(:@alias-names, :$canonical-name, :$ip-address);
}

#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     nimjgb.wwwww.com.
#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     p650nimjgb.wwwww.com.

grammar DIG-REVERSE {
    token TOP               { ^ <pointer-records>+ $ }
    token pointer-records   { ^^ <in-addr-arpa> \s+ \d+ \s+ 'IN' \s+ 'PTR' \s+ <name> '.' $$ \n }
    token in-addr-arpa      { $<octet-4> = \d ** 1..3 '.' $<octet-3> = \d ** 1..3 '.' $<octet-2> = \d ** 1..3 '.' $<octet-1> = \d ** 1..3 '.in-addr.arpa.' }
    token name              { ( \w || '-' || '.' <!before \s> )+ }
}

method !lookup-reverse (Str:D $ip-address!, :$resolution) {
    for @.dns-servers -> $dns-server {
        my @cmd     =   flat @base-cmd,
                        '@' ~ $dns-server,
                        '-x',
                        $ip-address,
                        'IN';
        my $proc    =   run @cmd, :out, :err;
        my $out     =   $proc.out.slurp(:close);
        my $err     =   $proc.err.slurp(:close);
        my $match   =   DIG-REVERSE.parse($out);
        if $match {
            my $analysis = self!analyze-reverse($match, :$resolution);
            return $analysis with $analysis;
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

#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     nimjgb.wwwww.com.
#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     p650nimjgb.wwwww.com.

method !analyze-reverse ($match, :$resolution) {
    return Nil unless $match ~~ Match;
    my @alias-names;
    my $canonical-name;
    my $ip-address;
    for $match<pointer-records> -> $record {

dd $record; die;
        if $record<address-record>:exists {
            $ip-address = $record<address-record><ip-address>.Str;
            $canonical-name = $record<address-record><canonical-name>.Str;
        }
        elsif $record<canonical-name-record>:exists {
            @alias-names.push: $record<canonical-name-record><alias-name>.Str;
            $canonical-name = $record<canonical-name-record><canonical-name>.Str;
        }
        else {
            die 'Should never happen...';
        }
    }
    return Nil unless $ip-address && $canonical-name;
    return Resolution.new(:@alias-names, :$canonical-name, :$ip-address);
}

=finish
