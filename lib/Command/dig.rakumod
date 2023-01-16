unit class Command::dig:api<1>:auth<Mark Devine (mark@markdevine.com)>;

use Terminal::ANSIColor;
use Prettier::Table;
use Data::Dump::Tree;
#use Grammar::Debugger;
#use Grammar::Tracer;

has         @.dns-servers   is rw   = [];
has         @.dns-domains   is rw   = [];

has         $.address;
has         @.aliases;
has         $.canonical;

submethod TWEAK {
#   $*ERR.put: colored(::?CLASS.raku ~ ".new()  :label or :address are required, minimally", 'red on_black') unless $!label || $!address;
}

#   Grammars

regex name                  { ( \w || '-' || '.' <!before \s> )+ }

#   P520TSMJGB.wwwww.com.   0       IN      CNAME   jatsmprd03.wwwww.com.
#   jatsmprd03.wwwww.com.   0       IN      A       10.10.137.41

grammar DIG-FORWARD {
    token TOP                   { ^ [ <address-record> || <canonical-name-record> ]+ }
    token address-record        { <canonical> '.' \s+ \d+ \s+ 'IN' \s+ 'A' \s+ <ip-address> $$ \n }
    token canonical-name-record { <alias> '.' \s+ \d+ \s+ 'IN' \s+ 'CNAME' \s+ <canonical> $$ \n }
    token ip-address            { $<octet-4> = \d ** 1..3 '.'
                                  $<octet-3> = \d ** 1..3 '.'
                                  $<octet-2> = \d ** 1..3 '.'
                                  $<octet-1> = \d ** 1..3 }
    regex alias                 { <name> }
    regex canonical             { <name> }
}

class DIG-FORWARD-ACTIONS {
    method ip-address ($/)  { make +$/<octet-1> ~ '.' ~ +$/<octet-2> ~ '.' ~ +$/<octet-3> ~ '.' ~ +$/<octet-4>; }
    method alias ($/)       { make $/<alias><name>; }
    method canonical ($/)   { make $/<canonical><name>; }
}

method resolve (Str:D $label-or-ipv4) {
#   if $label-or-ipv4 ~~ / ^ \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 '.' \d ** 1..3 $ / {
#       self.lookup-reverse($label-or-ipv4);
#   }
    if $label-or-ipv4 ~~ / ^ ( \w || '-' || '.' <!before \s> )+ $ / {
        self.lookup-forward($label-or-ipv4);
    }
    else {
        fail "Cannot reconcile if <$label-or-ipv4> is a name/label or an IP address";
    }
}

method lookup-forward (Str:D $ip-label!) {
    my @base-cmd    =   '/usr/bin/dig',
                        '-4',
                        '+nocomments',
                        '+nocmd',
                        '+nostats',
                        '+noedns',
                        '+nocookie',
                        '+noquestion',
                        '+noauthority',
                        '+noadditional';
    for @.dns-servers -> $dns-server {
        if @.dns-domains {
            for @.dns-domains -> $dns-domain {
                my @cmd     =   flat @base-cmd,
                                '+domain=' ~ $dns-domain, 
                                '@' ~ $dns-server,
                                $ip-label,
                                'A';
                my $proc    =   run flat @cmd, :out, :err;
                my $out     = $proc.out.slurp(:close);
                my $err     = $proc.err.slurp(:close);
                my $match   = DIG-FORWARD.parse($out, :actions(DIG-FORWARD-ACTIONS.new));
                with $match {
                    $!address   = $match<ip-address>.made;
                    @!aliases.push: $match<alias>.made with $match<alias>.made;
                    $!canonical = $match<canonical>.made;
                    return self.address;
                }
            }
        }
        else { ;
        }
    }
    if @.dns-domains { ;
    }
    else { ;
    }
    return Nil;
}

=finish

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

method lookup-reverse (Str:D $ip-address!, Str :$expectation) {
    for @.dns-servers -> $dns-server {
        for @.dns-domains -> $dns-domain {
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
