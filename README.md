dig - Command Runner
====================
Runs _dig_.


SYNOPSIS
========
```
    my dig $dig-obj .= new(
                            :label<host_to_lookup>,
                            :address<ip_to_lookup>,
                          );
    printf "%-17s%s\n", $dig-obj.canonical-ip, $dig-obj.canonical-label;
    .put for $dig-obj.aliases;
```

AUTHOR
======
Mark Devine <mark@markdevine.com>
