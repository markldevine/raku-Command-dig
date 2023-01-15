unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

use Terminal::ANSIColor;
use Prettier::Table;
use Data::Dump::Tree;
#use Grammar::Debugger;
#use Grammar::Tracer;

has Str     $.label;
has Str     $.address;
has Str     @.dns-servers   is required;
has Str     @.dns-domains;

has         @!records;

submethod TWEAK {
    fail ":label or :address are required minimally" unless $!label || $!address;
}

#   Grammars

#   P520TSMJGB.wwwww.com.   0       IN      CNAME   jatsmprd03.wwwww.com.
#   jatsmprd03.wwwww.com.   0       IN      A       10.10.137.41

grammar DIG-FORWARD {
    token TOP               { ^ [ <A-record> || <CNAME-record> ]+ }
    token A-record          { <name> '.' \s+ \d+ \s+ 'IN' \s+ 'A' \s+ <ip-addr> $$ \n }
    token CNAME-record      { <name> '.' \s+ \d+ \s+ 'IN' \s+ 'CNAME' \s+ <canonical-name> $$ \n }
    token ip-addr           { $<octet-4> = \d ** 1..3 '.' $<octet-3> = \d ** 1..3 '.' $<octet-2> = \d ** 1..3 '.' $<octet-1> = \d ** 1..3 }
    token record-type       { 'A' || 'CNAME' }
    regex name              { ( \w || '-' || '.' <!before \s> )+ }
    regex canonical-name    { ( \w || '-' || '.' <!before \s> )+ }
}

class DIG-FORWARD-ACTIONS {
    method system-clock-timestamp ($/) {
        make DateTime.new(
            year    => ~$/<year>,
            month   => ~$/<alpha-month>.made,
            day     => ~$/<day-of-month>,
            hour    => ~$/<hms><hours>,
            minute  => ~$/<hms><minutes>,
            second  => ~$/<hms><seconds>,
        );
    }
}

#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     nimjgb.wwwww.com.
#   194.1.121.170.in-addr.arpa. 259200 IN   PTR     p650nimjgb.wwwww.com.

grammar DIG-REVERSE {
    token TOP               { ^ <record>+ $ }
    token record            { ^^ <in-addr-arpa> \s+ \d+ \s+ 'IN' \s+ 'PTR' \s+ <name> '.' $$ \n }
    token in-addr-arpa      { $<octet-4> = \d ** 1..3 '.' $<octet-3> = \d ** 1..3 '.' $<octet-2> = \d ** 1..3 '.' $<octet-1> = \d ** 1..3 '.in-addr.arpa.' }
    regex name              { ( \w || '-' || '.' <!before \s> )+ }
}

class DIG-REVERSE-ACTIONS {
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
            my $match   = DIG-FORWARD.parse($out, :actions(DIG-FORWARD-ACTIONS.new);
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
            my $match   = DIG-REVERSE.parse($out);
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
    my $match   = DIG-REVERSE.parse($out);
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
