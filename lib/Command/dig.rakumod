unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

use Terminal::ANSIColor;
use Prettier::Table;
use Data::Dump::Tree;
#use Grammar::Debugger;
#use Grammar::Tracer;

has Str     $.label;
has Str     $.address;
has Str     @.dns-servers;
has Str     @.dns-domains;
has Bool    $.ipv4          = True;
has Bool    $.nocomments    = True;
has Bool    $.nocmd         = True;
has Bool    $.nostats       = True;
has Bool    $.noedns        = True;
has Bool    $.nocookie      = True;
has Bool    $.noquestion    = True;
has Bool    $.noauthority   = True;
has Bool    $.noadditional  = True;

submethod TWEAK {
}

method expose {
}

#   Grammars

#   P520TSMJGB.wmata.com.   0       IN      CNAME   jatsmprd03.wmata.com.
#   jatsmprd03.wmata.com.   0       IN      A       10.10.137.41

grammar DIG_FORWARD {
    token TOP {
        ^
        <record>+
    }
    token record {
        <name>
        '.'
        \s+
        \d+
        \s+
        'IN'
        \s+
        <type>
        \s+
        <ip-addr>
        $$
        \n
        $
    }
    token type {
        'A' || 'CNAME'
    }
    token ip-addr {
        $<octet-4> = \d ** 1..3 
        '.'
        $<octet-3> = \d ** 1..3 
        '.'
        $<octet-2> = \d ** 1..3 
        '.'
        $<octet-1> = \d ** 1..3 
    }
    token record-type {
        <A> || <CNAME>
    }
    token A {
        'A'
    }
    token CNAME {
        'CNAME'
    }
    regex name {
        ( \w || '-' || '.' <!before \s> )+
    }
}

#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     nimjgb.wmata.com.
#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     p650nimjgb.wmata.com.

grammar DIG_REVERSE {
    token TOP {
        ^
        <record>+
        $
    }
    token record {
        ^^
        <in-addr-arpa>
        \s+
        \d+
        \s+
        'IN'
        \s+
        'PTR'
        \s+
        <name>
        '.'
        $$
        \n
    }
    token in-addr-arpa {
        $<octet-4> = \d ** 1..3 
        '.'
        $<octet-3> = \d ** 1..3 
        '.'
        $<octet-2> = \d ** 1..3 
        '.'
        $<octet-1> = \d ** 1..3 
        '.in-addr.arpa.'
    }
    regex name {
        ( \w || '-' || '.' <!before \s> )+
    }
}

#   Check if supplied hostname/iplabel is resolvable into an IP address

method lookup-forward (Str:D $ip-label!) {
    for @dns-servers.pick -> $dns-server {
        for @dns-domains -> $dns-domain {
            my $proc    = run   '/usr/bin/dig',
                                '-4',
                                '+nocomments',
                                '+nocmd',
                                '+nostats',
                                '+noedns',
                                '+nocookie',
                                '+noquestion',
                                '+noauthority',
                                '+noadditional',
                                '+domain=' ~ $dns-domain,
                                '@' ~ $dns-server,
                                $ip-label,
                                'A',
                                :out,
                                :err;
            my $out     = $proc.out.slurp(:close);
            my $err     = $proc.err.slurp(:close);
            my $match   = DIG_FORWARD.parse($out);
            return $match<ip-addr>.Str with $match;
        }
    }
    fail colored("lookup-forward '$ip-label' failed!", 'red on_black');
}

method lookup-reverse (Str:D $ip-address!, Str :$expectation) {
    for @dns-servers -> $dns-server {
        for @dns-domains -> $dns-domain {
            my $proc    = run   '/usr/bin/dig',
                                '-4',
                                '+nocomments',
                                '+nocmd',
                                '+nostats',
                                '+noedns',
                                '+nocookie',
                                '+noquestion',
                                '+noauthority',
                                '+noadditional',
                                '+domain=' ~ $dns-domain,
                                '@' ~ $dns-server,
                                '-x',
                                $ip-address,
                                'IN',
                                :out,
                                :err;
            my $out     = $proc.out.slurp(:close);
            my $err     = $proc.err.slurp(:close);
            my $match   = DIG_REVERSE.parse($out);
            with $match {
                with $expectation {
                    for $match<record> -> $record {
                        return $record<name>.Str if $record<name>.Str ~~ m:i/ ^ $expectation /;
                    }
                }
                return $match<record> if $match<record>:exists;
            }
        }
    }
#   Without specific DNS server...
    my $proc    = run   '/usr/bin/dig',
                        '-4',
                        '+nocomments',
                        '+nocmd',
                        '+nostats',
                        '+noedns',
                        '+nocookie',
                        '+noquestion',
                        '+noauthority',
                        '+noadditional',
                        '-x',
                        $ip-address,
                        'IN',
                        :out,
                        :err;
    my $out     = $proc.out.slurp(:close);
    my $err     = $proc.err.slurp(:close);
    my $match   = DIG_REVERSE.parse($out);
    with $match {
        with $expectation {
            for $match<record> -> $record {
                return $record<name>.Str if $record<name>.Str ~~ m:i/ ^ $expectation /;
            }
        }
        return $match<record> if $match<record>:exists;
    }
    fail colored("lookup-reverse '$ip-address' failed!", 'red on_black');
}

=finish
