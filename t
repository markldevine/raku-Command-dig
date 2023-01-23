#!/usr/bin/env raku

use lib '/home/mdevine/github.com/raku-Command-dig/lib';
use Command::dig;
use Prettier::Table;

my Command::dig $digger    .= new(
                                     :dns-servers<10.10.43.40 10.10.43.40 170.121.18.30 170.121.218.30>,
                                     :dns-domains<wmata.com wmata.local ncs.wmata.com video.wmata.com>,
                                 );


my @unknowns                = [
#                               'www.google.com',
#                               '10.10.137.41',
#                               '10.11.101.230',
#                               '10.11.105.96',
#                               '170.121.1.194',
#                               'JATSMPRD03',
                                'P520TSMJGB',
#                               'ctstmgtgate1lpv',
#                               'isplc02',
#                               'nimjgb',
#                               'p650nimjgb',
                              ];

my $table = Prettier::Table.new:
    title       => "Resolution Summary",
    field-names => ['Canonical Name', 'IP Address', 'Alias Names'],
    align       => %('Canonical Name' => 'l', 'IP Address' => 'l', 'Alias Names' => 'l'),
    hrules      => Prettier::Table::Constrains::ALL,
;

#   ip-address => "", alias-names => {}, canonical-name => "", pointer-names => [])
for @unknowns -> $unknown {
    my $resolution  = $digger.resolve($unknown);
    my @alias-names = $resolution.alias-names.keys.sort;
    $table.add-row: [
                        $resolution.canonical-name,
                        join("\n", $resolution.ip-addresses.keys),
                        @alias-names.join: "\n";
                    ];
}

put $table;

=finish
