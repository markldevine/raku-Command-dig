dig - Command Runner
====================
Runs _dig_.


SYNOPSIS
========
```
    my Command::dig $resolution .= new(
                                       :dns-servers<10.10.10.10 10.11.11.11>,
                                       :dns-domains<sales.business.com business.com>,
                                      );
    printf "%-17s%s\n", $resolution.ip-address, $resolution.canonical-name;
    .put for $resolution.alias-names;
```

AUTHOR
======
Mark Devine <mark@markdevine.com>
